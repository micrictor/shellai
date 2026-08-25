import argparse
import json
import math
import random
import time
from pathlib import Path

import torch
import torch.nn as nn
from datasets import load_from_disk
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

from models.seq2seq_rnn import (
    AttentionDecoderRNN,
    EncoderRNN,
    Seq2SeqAttention,
)
from models.seq2seq_lstm import (
    AttentionDecoderLSTM,
    EncoderLSTM,
    Seq2SeqAttentionLSTM,
)


class TextPairDataset(Dataset):
    def __init__(
        self,
        hf_dataset,
        tokenizer,
        decoder_start_token_id,
        max_src_len=128,
        max_trg_len=128,
    ):
        self.samples = hf_dataset
        self.tokenizer = tokenizer
        self.decoder_start_token_id = decoder_start_token_id
        self.max_src_len = max_src_len
        self.max_trg_len = max_trg_len
        self.pad_token_id = tokenizer.pad_token_id
        self.eos_token_id = tokenizer.eos_token_id

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        item = self.samples[idx]
        src_ids = self.tokenizer(
            item["nl"],
            max_length=self.max_src_len,
            padding="max_length",
            truncation=True,
        )["input_ids"]

        # The decoder input must begin with a start token. T5 uses PAD as its
        # decoder-start token; using the first Bash token here silently prevents
        # the model from ever learning that first output token.
        target_ids = self.tokenizer(
            item["bash"],
            add_special_tokens=True,
            max_length=self.max_trg_len - 1,
            truncation=True,
        )["input_ids"]
        if target_ids and target_ids[-1] != self.eos_token_id:
            target_ids[-1] = self.eos_token_id
        trg_ids = [self.decoder_start_token_id, *target_ids]
        trg_ids.extend([self.pad_token_id] * (self.max_trg_len - len(trg_ids)))

        return {
            "src": torch.tensor(src_ids, dtype=torch.long),
            "trg": torch.tensor(trg_ids, dtype=torch.long),
        }


def make_trimmed_collate(pad_token_id):
    """Stack a batch and remove padding columns unused by every example."""

    def collate(batch):
        src = torch.stack([item["src"] for item in batch])
        trg = torch.stack([item["trg"] for item in batch])
        source_length = int(src.ne(pad_token_id).sum(dim=1).max())
        # T5's decoder-start token is PAD, so add its leading position back.
        target_length = int(trg.ne(pad_token_id).sum(dim=1).max()) + 1
        return {
            "src": src[:, :source_length],
            "trg": trg[:, :target_length],
        }

    return collate


def _seed_everything(seed):
    random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def _load_splits(dataset_dir):
    dataset = load_from_disk(str(dataset_dir))
    if "validation" not in dataset:
        if "test" not in dataset:
            raise ValueError("Dataset needs a validation split (or legacy test split).")
        print(
            "WARNING: legacy dataset has no validation split; using test for "
            "validation. Regenerate the dataset before reporting final metrics."
        )
        return dataset["train"], dataset["test"]
    return dataset["train"], dataset["validation"]


def _save_checkpoint(path, model, optimizer, config, history, epoch):
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "optimizer_state_dict": optimizer.state_dict(),
            **config,
            "history": history,
            "epoch": epoch,
        },
        path,
    )


def train_model(
    model_variant,
    dataset_dir,
    tokenizer_name="google/flan-t5-small",
    epochs=3,
    batch_size=32,
    learning_rate=1e-3,
    embed_dim=256,
    hidden_dim=256,
    max_source_length=128,
    max_target_length=128,
    seed=42,
    log_steps=100,
    freeze_embeddings=False,
    architecture="gru",
    dry_run=False,
):
    if model_variant not in {"seq2seq-scratch", "seq2seq-transfer"}:
        raise ValueError(f"Unknown model variant: {model_variant}")
    if architecture not in {"gru", "lstm"}:
        raise ValueError(f"Unknown architecture: {architecture}")

    _seed_everything(seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(
        f"\nTraining {architecture.upper()} {model_variant} on {device} | epochs={epochs} | "
        f"batch_size={batch_size}"
    )

    train_split, validation_split = _load_splits(Path(dataset_dir))
    tokenizer = AutoTokenizer.from_pretrained(tokenizer_name)
    if tokenizer.pad_token_id is None or tokenizer.eos_token_id is None:
        raise ValueError("Tokenizer must define pad_token_id and eos_token_id.")

    vocab_size = len(tokenizer)
    decoder_start_token_id = tokenizer.pad_token_id
    pretrained_embeddings = None
    if model_variant == "seq2seq-transfer":
        print(f"Loading pretrained embeddings from {tokenizer_name}...")
        base_model = AutoModelForSeq2SeqLM.from_pretrained(tokenizer_name)
        weights = base_model.get_input_embeddings().weight.detach().cpu()
        if weights.shape[0] < vocab_size:
            raise ValueError(
                f"Model embeddings do not cover tokenizer vocabulary: {vocab_size} vs "
                f"{weights.shape[0]}"
            )
        if weights.shape[0] > vocab_size:
            # T5 pads its embedding matrix to a hardware-friendly multiple even
            # though those extra rows are unreachable from the tokenizer.
            weights = weights[:vocab_size]
        embed_dim = weights.shape[1]
        pretrained_embeddings = weights.numpy()
        del base_model

    train_ds = TextPairDataset(
        train_split,
        tokenizer,
        decoder_start_token_id,
        max_source_length,
        max_target_length,
    )
    validation_ds = TextPairDataset(
        validation_split,
        tokenizer,
        decoder_start_token_id,
        max_source_length,
        max_target_length,
    )
    generator = torch.Generator().manual_seed(seed)
    collate_fn = make_trimmed_collate(tokenizer.pad_token_id)
    train_loader = DataLoader(
        train_ds,
        batch_size=batch_size,
        shuffle=True,
        generator=generator,
        num_workers=0,
        pin_memory=device.type == "cuda",
        collate_fn=collate_fn,
    )
    validation_loader = DataLoader(
        validation_ds,
        batch_size=batch_size,
        shuffle=False,
        num_workers=0,
        pin_memory=device.type == "cuda",
        collate_fn=collate_fn,
    )

    encoder_class = EncoderLSTM if architecture == "lstm" else EncoderRNN
    decoder_class = (
        AttentionDecoderLSTM if architecture == "lstm" else AttentionDecoderRNN
    )
    model_class = (
        Seq2SeqAttentionLSTM if architecture == "lstm" else Seq2SeqAttention
    )
    encoder = encoder_class(
        vocab_size,
        embed_dim,
        hidden_dim,
        pretrained_embeddings=pretrained_embeddings,
        padding_idx=tokenizer.pad_token_id,
    )
    decoder = decoder_class(
        vocab_size,
        embed_dim,
        hidden_dim,
        pretrained_embeddings=pretrained_embeddings,
        padding_idx=tokenizer.pad_token_id,
    )
    if architecture == "lstm" or model_variant == "seq2seq-transfer":
        # The LSTM uses a tied lexical input/output space. FLAN-T5 also shares
        # its token embeddings, so retain that inductive bias for GRU transfer.
        decoder.embedding = encoder.embedding
    if model_variant == "seq2seq-transfer":
        encoder.embedding.weight.requires_grad_(not freeze_embeddings)

    model = model_class(
        encoder,
        decoder,
        pad_idx=tokenizer.pad_token_id,
        sos_idx=decoder_start_token_id,
        eos_idx=tokenizer.eos_token_id,
    ).to(device)
    total_params = sum(parameter.numel() for parameter in model.parameters())
    trainable_params = sum(
        parameter.numel() for parameter in model.parameters() if parameter.requires_grad
    )
    print(
        f"Parameters: {total_params:,} total, {trainable_params:,} trainable | "
        f"train={len(train_ds):,}, validation={len(validation_ds):,}"
    )
    if dry_run:
        print("Dry run complete; no training or checkpoints were written.")
        return None

    criterion = nn.CrossEntropyLoss(ignore_index=tokenizer.pad_token_id)
    optimizer = torch.optim.AdamW(
        (parameter for parameter in model.parameters() if parameter.requires_grad),
        lr=learning_rate,
    )
    checkpoint_name = (
        model_variant
        if architecture == "gru"
        else f"lstm-{model_variant}"
    )
    save_dir = Path("checkpoints") / checkpoint_name
    history = []
    best_validation_loss = math.inf
    started_at = time.time()
    config = {
        "vocab_size": vocab_size,
        "embed_dim": embed_dim,
        "hidden_dim": hidden_dim,
        "tokenizer_name": tokenizer_name,
        "pad_idx": tokenizer.pad_token_id,
        "sos_idx": decoder_start_token_id,
        "eos_idx": tokenizer.eos_token_id,
        "params": total_params,
        "model_variant": model_variant,
        "architecture": architecture,
        "max_source_length": max_source_length,
        "max_target_length": max_target_length,
    }

    for epoch in range(1, epochs + 1):
        model.train()
        running_loss = 0.0
        for step, batch in enumerate(train_loader, start=1):
            src = batch["src"].to(device, non_blocking=True)
            trg = batch["trg"].to(device, non_blocking=True)
            optimizer.zero_grad(set_to_none=True)
            logits = model(src, trg, teacher_forcing_ratio=0.5)
            loss = criterion(
                logits[:, 1:].reshape(-1, logits.shape[-1]),
                trg[:, 1:].reshape(-1),
            )
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            running_loss += loss.item()
            if step % log_steps == 0:
                print(
                    f"epoch {epoch}/{epochs} step {step}/{len(train_loader)} "
                    f"train_loss={running_loss / step:.4f}",
                    flush=True,
                )

        model.eval()
        validation_loss = 0.0
        with torch.inference_mode():
            for batch in validation_loader:
                src = batch["src"].to(device, non_blocking=True)
                trg = batch["trg"].to(device, non_blocking=True)
                # Teacher forcing gives a comparable conditional validation loss;
                # generation quality is measured separately on the official test.
                logits = model(src, trg, teacher_forcing_ratio=1.0)
                validation_loss += criterion(
                    logits[:, 1:].reshape(-1, logits.shape[-1]),
                    trg[:, 1:].reshape(-1),
                ).item()

        train_loss = running_loss / len(train_loader)
        validation_loss /= len(validation_loader)
        history.append(
            {
                "epoch": epoch,
                "train_loss": train_loss,
                "validation_loss": validation_loss,
            }
        )
        print(
            f"epoch {epoch}/{epochs} complete | train_loss={train_loss:.4f} | "
            f"validation_loss={validation_loss:.4f} | "
            f"elapsed={time.time() - started_at:.1f}s",
            flush=True,
        )
        _save_checkpoint(
            save_dir / f"checkpoint-epoch-{epoch}.pt",
            model,
            optimizer,
            config,
            history,
            epoch,
        )
        if validation_loss < best_validation_loss:
            best_validation_loss = validation_loss
            _save_checkpoint(
                save_dir / "best_model.pt",
                model,
                optimizer,
                config,
                history,
                epoch,
            )

    final_path = save_dir / "seq2seq_model.pt"
    _save_checkpoint(final_path, model, optimizer, config, history, epochs)
    (save_dir / "training_history.json").write_text(
        json.dumps(history, indent=2), encoding="utf-8"
    )
    print(f"Saved final checkpoint to '{final_path}'")
    return final_path


def parse_args():
    parser = argparse.ArgumentParser(description="Train the custom attention seq2seq model.")
    parser.add_argument(
        "--variant",
        choices=["seq2seq-scratch", "seq2seq-transfer"],
        default="seq2seq-transfer",
    )
    parser.add_argument(
        "--architecture",
        choices=["gru", "lstm"],
        default="gru",
    )
    parser.add_argument("--dataset-dir", default="data/nl2sh-alfa-synth")
    parser.add_argument("--tokenizer-name", default="google/flan-t5-small")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--embed-dim", type=int, default=256)
    parser.add_argument("--hidden-dim", type=int, default=256)
    parser.add_argument("--max-source-length", type=int, default=128)
    parser.add_argument("--max-target-length", type=int, default=128)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--log-steps", type=int, default=100)
    parser.add_argument("--freeze-embeddings", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    train_model(
        model_variant=args.variant,
        dataset_dir=args.dataset_dir,
        tokenizer_name=args.tokenizer_name,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        embed_dim=args.embed_dim,
        hidden_dim=args.hidden_dim,
        max_source_length=args.max_source_length,
        max_target_length=args.max_target_length,
        seed=args.seed,
        log_steps=args.log_steps,
        freeze_embeddings=args.freeze_embeddings,
        architecture=args.architecture,
        dry_run=args.dry_run,
    )
