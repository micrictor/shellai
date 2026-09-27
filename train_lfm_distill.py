"""Logit-distill LFM2-350M from LFM2.5-2.6B for NL-to-Bash.

The two checkpoints do not share a vocabulary.  This script first transplants
the student's learned input/output rows into the teacher tokenizer by matching
token strings.  Once both models use identical token IDs, ordinary token-level
KL distillation is well-defined.
"""

import argparse
import json
import math
import random
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from datasets import DatasetDict, load_dataset
from torch.utils.data import DataLoader
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    get_cosine_schedule_with_warmup,
)


SYSTEM_PROMPT = (
    "You translate natural-language requests into exactly one Bash command. "
    "Return only the command, with no Markdown, explanation, or alternatives."
)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--student-model", default="LiquidAI/LFM2-350M")
    parser.add_argument("--teacher-model", default="LiquidAI/LFM2.5-2.6B")
    parser.add_argument("--dataset", default="westenfelder/NL2SH-ALFA")
    parser.add_argument("--dataset-config", default="train")
    parser.add_argument("--output-dir", default="checkpoints/lfm2-nl2bash-distilled")
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=2)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--weight-decay", type=float, default=0.1)
    parser.add_argument("--warmup-ratio", type=float, default=0.05)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--max-answer-tokens", type=int, default=96)
    parser.add_argument("--temperature", type=float, default=2.0)
    parser.add_argument(
        "--distill-weight",
        type=float,
        default=0.7,
        help="Weight on teacher KL; the remainder weights gold-label CE.",
    )
    parser.add_argument("--validation-fraction", type=float, default=0.05)
    parser.add_argument("--max-train-samples", type=int, default=None)
    parser.add_argument("--max-validation-samples", type=int, default=500)
    parser.add_argument("--logging-steps", type=int, default=10)
    parser.add_argument("--save-every-epoch", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--gradient-checkpointing", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--resume-from", default=None)
    parser.add_argument("--push-to-hub", default=None, metavar="REPO_ID")
    return parser.parse_args()


def seed_everything(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def build_token_map(source_tokenizer, target_tokenizer):
    """Return target IDs and corresponding source IDs for identical tokens."""
    source_vocab = source_tokenizer.get_vocab()
    target_vocab = target_tokenizer.get_vocab()
    pairs = sorted(
        (target_id, source_vocab[token])
        for token, target_id in target_vocab.items()
        if token in source_vocab
    )
    target_ids = torch.tensor([pair[0] for pair in pairs], dtype=torch.long)
    source_ids = torch.tensor([pair[1] for pair in pairs], dtype=torch.long)
    return target_ids, source_ids


def transplant_student_vocabulary(student, source_tokenizer, target_tokenizer):
    """Resize and remap student embeddings/LM head to target tokenizer IDs."""
    parameters_before = sum(parameter.numel() for parameter in student.parameters())
    was_tied = (
        student.get_input_embeddings().weight.data_ptr()
        == student.get_output_embeddings().weight.data_ptr()
    )
    old_input = student.get_input_embeddings().weight.detach().cpu().clone()
    output_layer = student.get_output_embeddings()
    old_output = output_layer.weight.detach().cpu().clone()
    old_bias = (
        output_layer.bias.detach().cpu().clone()
        if getattr(output_layer, "bias", None) is not None
        else None
    )
    target_ids, source_ids = build_token_map(source_tokenizer, target_tokenizer)

    student.resize_token_embeddings(len(target_tokenizer), mean_resizing=False)
    new_input = student.get_input_embeddings().weight
    new_output_layer = student.get_output_embeddings()
    new_output = new_output_layer.weight
    with torch.no_grad():
        for start in range(0, len(target_ids), 4096):
            end = start + 4096
            dst = target_ids[start:end].to(new_input.device)
            src = source_ids[start:end]
            new_input.index_copy_(0, dst, old_input.index_select(0, src).to(new_input.device))
            if not was_tied:
                new_output.index_copy_(
                    0, dst, old_output.index_select(0, src).to(new_output.device)
                )
            if old_bias is not None:
                new_output_layer.bias.index_copy_(
                    0, dst, old_bias.index_select(0, src).to(new_output_layer.bias.device)
                )

    # The target tokenizer supplies every special-token ID used in training and
    # generation.  Keep model and generation configs synchronized with it.
    for name in ("bos_token_id", "eos_token_id", "pad_token_id"):
        value = getattr(target_tokenizer, name)
        setattr(student.config, name, value)
        if getattr(student, "generation_config", None) is not None:
            setattr(student.generation_config, name, value)

    stats = {
        "source_vocab_size": len(source_tokenizer),
        "target_vocab_size": len(target_tokenizer),
        "exactly_remapped_tokens": len(target_ids),
        "newly_initialized_tokens": len(target_tokenizer) - len(target_ids),
        "input_output_embeddings_were_tied": was_tied,
        "parameters_before": parameters_before,
        "parameters_after": sum(parameter.numel() for parameter in student.parameters()),
    }
    return stats


def prompt_text(nl):
    return (
        "<|startoftext|><|im_start|>system\n"
        f"{SYSTEM_PROMPT}<|im_end|>\n"
        "<|im_start|>user\n"
        f"Generate one Bash command: {str(nl).strip()}<|im_end|>\n"
        "<|im_start|>assistant\n<think></think>\n"
    )


def prepare_datasets(args, tokenizer):
    raw = load_dataset(args.dataset, args.dataset_config)
    if not isinstance(raw, DatasetDict):
        raw = DatasetDict({"train": raw})
    if "validation" not in raw:
        split = raw["train"].train_test_split(
            test_size=args.validation_fraction, seed=args.seed, shuffle=True
        )
        raw = DatasetDict({"train": split["train"], "validation": split["test"]})

    if args.max_train_samples is not None:
        raw["train"] = raw["train"].select(
            range(min(args.max_train_samples, len(raw["train"])))
        )
    if args.max_validation_samples is not None:
        raw["validation"] = raw["validation"].select(
            range(min(args.max_validation_samples, len(raw["validation"])))
        )

    def encode(row):
        prompt_ids = tokenizer.encode(prompt_text(row["nl"]), add_special_tokens=False)
        answer_ids = tokenizer.encode(
            str(row["bash"]).strip() + "<|im_end|>\n", add_special_tokens=False
        )[: args.max_answer_tokens]
        if len(answer_ids) < 2:
            raise ValueError("Encountered an empty Bash answer")
        prompt_budget = args.max_length - len(answer_ids)
        if prompt_budget < 1:
            answer_ids = answer_ids[: args.max_length - 1]
            prompt_budget = 1
        # Preserve the user/assistant boundary if an unusually long request
        # must be truncated. Normal NL2SH examples fit without truncation.
        prompt_ids = prompt_ids[-prompt_budget:]
        input_ids = prompt_ids + answer_ids
        labels = [-100] * len(prompt_ids) + answer_ids
        return {"input_ids": input_ids, "labels": labels}

    remove_columns = raw["train"].column_names
    encoded = raw.map(encode, remove_columns=remove_columns, desc="Tokenizing NL2Bash")
    return encoded


class DistillCollator:
    def __init__(self, pad_token_id):
        self.pad_token_id = pad_token_id

    def __call__(self, rows):
        width = max(len(row["input_ids"]) for row in rows)
        input_ids, labels, attention_mask = [], [], []
        for row in rows:
            padding = width - len(row["input_ids"])
            input_ids.append(row["input_ids"] + [self.pad_token_id] * padding)
            labels.append(row["labels"] + [-100] * padding)
            attention_mask.append([1] * len(row["input_ids"]) + [0] * padding)
        return {
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "labels": torch.tensor(labels, dtype=torch.long),
            "attention_mask": torch.tensor(attention_mask, dtype=torch.long),
        }


def loss_components(student, teacher, batch, temperature, distill_weight):
    inputs = {
        "input_ids": batch["input_ids"],
        "attention_mask": batch["attention_mask"],
        "use_cache": False,
    }
    student_logits = student(**inputs).logits[:, :-1]
    with torch.no_grad():
        teacher_logits = teacher(**inputs).logits[:, :-1]
    targets = batch["labels"][:, 1:]
    active = targets.ne(-100)
    if not active.any():
        raise RuntimeError("Batch contains no answer tokens")

    # Select answer positions before converting to fp32.  This keeps exact
    # full-vocabulary KL practical even with the teacher's 128k vocabulary.
    student_active = student_logits[active].float()
    teacher_active = teacher_logits[active].float()
    hard = F.cross_entropy(student_active, targets[active])
    soft = F.kl_div(
        F.log_softmax(student_active / temperature, dim=-1),
        F.softmax(teacher_active / temperature, dim=-1),
        reduction="batchmean",
    ) * (temperature**2)
    total = (1.0 - distill_weight) * hard + distill_weight * soft
    return total, hard.detach(), soft.detach(), int(active.sum())


@torch.no_grad()
def validate(student, teacher, loader, device, args):
    student.eval()
    teacher.eval()
    totals = np.zeros(4, dtype=np.float64)
    for batch in loader:
        batch = {key: value.to(device) for key, value in batch.items()}
        with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
            loss, hard, soft, tokens = loss_components(
                student, teacher, batch, args.temperature, args.distill_weight
            )
        totals += [float(loss), float(hard), float(soft), 1]
    student.train()
    return {
        "validation_loss": totals[0] / max(totals[3], 1),
        "validation_ce": totals[1] / max(totals[3], 1),
        "validation_kl": totals[2] / max(totals[3], 1),
    }


def save_checkpoint(path, student, tokenizer, optimizer, scheduler, state, args):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    student.save_pretrained(path, safe_serialization=True, max_shard_size="2GB")
    tokenizer.save_pretrained(path)
    torch.save(
        {
            "optimizer": optimizer.state_dict(),
            "scheduler": scheduler.state_dict(),
            "state": state,
        },
        path / "training_state.pt",
    )
    (path / "distillation_config.json").write_text(
        json.dumps(vars(args), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def save_inference_model(path, student, tokenizer, transplant_stats, args):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    student.config.use_cache = True
    student.save_pretrained(path, safe_serialization=True, max_shard_size="2GB")
    tokenizer.save_pretrained(path)
    (path / "distillation_config.json").write_text(
        json.dumps(vars(args), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (path / "vocabulary_transplant.json").write_text(
        json.dumps(transplant_stats, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main():
    args = parse_args()
    if not torch.cuda.is_available():
        raise RuntimeError("This run requires a CUDA GPU; select an A100 Colab runtime")
    if torch.cuda.get_device_capability()[0] < 8:
        raise RuntimeError("BF16 requires an Ampere-or-newer CUDA GPU")
    if not 0 <= args.distill_weight <= 1:
        raise ValueError("--distill-weight must be between 0 and 1")
    seed_everything(args.seed)
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.set_float32_matmul_precision("high")
    device = torch.device("cuda")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Loading tokenizers and the fp32 student...")
    tokenizer = AutoTokenizer.from_pretrained(
        args.resume_from or args.teacher_model
    )
    if args.resume_from:
        student = AutoModelForCausalLM.from_pretrained(
            args.resume_from, torch_dtype=torch.float32, low_cpu_mem_usage=True
        )
        stats_path = Path(args.resume_from) / "vocabulary_transplant.json"
        if not stats_path.exists():
            stats_path = Path(args.resume_from).parent / "vocabulary_transplant.json"
        transplant_stats = (
            json.loads(stats_path.read_text(encoding="utf-8"))
            if stats_path.exists()
            else {"resumed_from": args.resume_from}
        )
    else:
        source_tokenizer = AutoTokenizer.from_pretrained(args.student_model)
        student = AutoModelForCausalLM.from_pretrained(
            args.student_model, torch_dtype=torch.float32, low_cpu_mem_usage=True
        )
        transplant_stats = transplant_student_vocabulary(
            student, source_tokenizer, tokenizer
        )
        del source_tokenizer
    print(json.dumps(transplant_stats, indent=2))
    (output_dir / "vocabulary_transplant.json").write_text(
        json.dumps(transplant_stats, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    student.config.use_cache = False
    if args.gradient_checkpointing:
        student.gradient_checkpointing_enable()
    student.to(device)

    print("Loading frozen BF16 teacher...")
    teacher = AutoModelForCausalLM.from_pretrained(
        args.teacher_model,
        torch_dtype=torch.bfloat16,
        low_cpu_mem_usage=True,
    ).to(device)
    teacher.eval()
    teacher.requires_grad_(False)
    teacher.config.use_cache = False
    if student.config.vocab_size != teacher.config.vocab_size:
        raise RuntimeError("Vocabulary transplant failed: output sizes still differ")

    encoded = prepare_datasets(args, tokenizer)
    collator = DistillCollator(tokenizer.pad_token_id)
    generator = torch.Generator().manual_seed(args.seed)
    train_loader = DataLoader(
        encoded["train"],
        batch_size=args.batch_size,
        shuffle=True,
        generator=generator,
        collate_fn=collator,
        pin_memory=True,
        num_workers=2,
    )
    validation_loader = DataLoader(
        encoded["validation"],
        batch_size=args.batch_size,
        shuffle=False,
        collate_fn=collator,
        pin_memory=True,
        num_workers=2,
    )
    updates_per_epoch = math.ceil(
        len(train_loader) / args.gradient_accumulation_steps
    )
    total_updates = updates_per_epoch * args.epochs
    optimizer = torch.optim.AdamW(
        student.parameters(),
        lr=args.learning_rate,
        betas=(0.9, 0.95),
        eps=1e-8,
        weight_decay=args.weight_decay,
        fused=True,
    )
    scheduler = get_cosine_schedule_with_warmup(
        optimizer,
        num_warmup_steps=max(1, int(total_updates * args.warmup_ratio)),
        num_training_steps=total_updates,
    )
    state = {"epoch": 0, "global_step": 0, "micro_step": 0}
    if args.resume_from:
        resume = torch.load(
            Path(args.resume_from) / "training_state.pt",
            map_location="cpu",
            weights_only=False,
        )
        optimizer.load_state_dict(resume["optimizer"])
        scheduler.load_state_dict(resume["scheduler"])
        state.update(resume["state"])
        print(f"Resuming after epoch {state['epoch']} at step {state['global_step']}")

    student.train()
    optimizer.zero_grad(set_to_none=True)
    autocast_factory = lambda: torch.autocast(
        device_type="cuda", dtype=torch.bfloat16
    )
    for epoch in range(state["epoch"], args.epochs):
        running = np.zeros(4, dtype=np.float64)
        for batch_index, batch in enumerate(train_loader, start=1):
            batch = {
                key: value.to(device, non_blocking=True) for key, value in batch.items()
            }
            sync_step = (
                batch_index % args.gradient_accumulation_steps == 0
                or batch_index == len(train_loader)
            )
            with autocast_factory():
                loss, hard, soft, tokens = loss_components(
                    student, teacher, batch, args.temperature, args.distill_weight
                )
                scaled_loss = loss / args.gradient_accumulation_steps
            scaled_loss.backward()
            state["micro_step"] += 1
            running += [float(loss), float(hard), float(soft), 1]

            if sync_step:
                torch.nn.utils.clip_grad_norm_(student.parameters(), 1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad(set_to_none=True)
                state["global_step"] += 1
                if state["global_step"] % args.logging_steps == 0:
                    denom = max(running[3], 1)
                    print(
                        f"epoch={epoch + 1}/{args.epochs} "
                        f"step={state['global_step']}/{total_updates} "
                        f"loss={running[0] / denom:.4f} "
                        f"ce={running[1] / denom:.4f} "
                        f"kl={running[2] / denom:.4f} "
                        f"lr={scheduler.get_last_lr()[0]:.2e}",
                        flush=True,
                    )
                    running.fill(0)

        metrics = validate(student, teacher, validation_loader, device, args)
        state["epoch"] = epoch + 1
        state.update(metrics)
        print(json.dumps({"epoch": epoch + 1, **metrics}, indent=2))
        if args.save_every_epoch:
            save_checkpoint(
                output_dir / "checkpoint-last",
                student,
                tokenizer,
                optimizer,
                scheduler,
                state,
                args,
            )

    final_dir = output_dir / "final"
    save_inference_model(final_dir, student, tokenizer, transplant_stats, args)
    if args.push_to_hub:
        student.push_to_hub(args.push_to_hub, safe_serialization=True)
        tokenizer.push_to_hub(args.push_to_hub)
    print(f"Finished. Full-precision deployable checkpoint: {final_dir}")


if __name__ == "__main__":
    main()
