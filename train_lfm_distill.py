"""Logit-distill Qwen3-0.6B from Qwen3.8-27B for NL-to-Bash.

The two checkpoints do not share a vocabulary.  This script first transplants
the student's learned input/output rows into the teacher tokenizer by matching
token strings.  Once both models use identical token IDs, ordinary token-level
KL distillation is well-defined.
"""

import argparse
import copy
import hashlib
import json
import math
import os
import random
from collections.abc import Mapping
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
import transformers
from datasets import DatasetDict, load_dataset
from safetensors.torch import load_file, save_file
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import (
    AutoConfig,
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
)


SYSTEM_PROMPT = (
    "You translate natural-language requests into exactly one Bash command. "
    "Return only the command, with no Markdown, explanation, or alternatives."
)

# A deliberately small text-only Qwen template. It normalizes ShellAI's
# existing messages to the exact non-thinking prompt used for distillation.
SHELLAI_CHAT_TEMPLATE = r'''{%- set shellai_system = "You translate natural-language requests into exactly one Bash command. Return only the command, with no Markdown, explanation, or alternatives." -%}
{{- "<|im_start|>system\n" + shellai_system + "<|im_end|>\n" }}
{%- for message in messages %}
{%- if message["role"] == "user" %}
{{- "<|im_start|>user\n" + (message["content"] | replace("Generate single Bash command: ", "Generate one Bash command: ")) + "<|im_end|>\n" }}
{%- elif message["role"] == "assistant" %}
{{- "<|im_start|>assistant\n<think>\n\n</think>\n\n" + message["content"] + "<|im_end|>\n" }}
{%- endif %}
{%- endfor %}
{%- if add_generation_prompt %}
{{- "<|im_start|>assistant\n<think>\n\n</think>\n\n" }}
{%- endif %}'''


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--student-model", default="Qwen/Qwen3-0.6B")
    parser.add_argument(
        "--teacher-model",
        default="Qwen/Qwen3.8-27B-FP8",
        help="Qwen3.8 teacher checkpoint; official FP8 is the G4/Blackwell default.",
    )
    parser.add_argument("--dataset", default="westenfelder/NL2SH-ALFA")
    parser.add_argument("--dataset-config", default="train")
    parser.add_argument("--output-dir", default="checkpoints/qwen3-0.6b-qwen38-nl2bash-distilled")
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=16)
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
    parser.add_argument(
        "--teacher-load-in-4bit",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Runtime-quantize an unquantized teacher to NF4; ignored for FP8/pre-quantized teachers.",
    )
    parser.add_argument(
        "--vocabulary-bridge-dir",
        default=None,
        help="Where to save the reusable pre-training vocabulary/output bridge (default: OUTPUT/vocabulary-bridge).",
    )
    parser.add_argument(
        "--reuse-vocabulary-bridge",
        default=None,
        help="Load a previously saved bridge instead of rebuilding expanded embeddings.",
    )
    parser.add_argument(
        "--save-vocabulary-bridge",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--resume-from", default=None)
    parser.add_argument("--push-to-hub", default=None, metavar="REPO_ID")
    return parser.parse_args()


def seed_everything(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def causal_lm_config(config):
    """Return the text config for either a text-only or nested VLM checkpoint."""
    return getattr(config, "text_config", config)


def quantization_method(config):
    quantization = getattr(config, "quantization_config", None)
    if isinstance(quantization, Mapping):
        return quantization.get("quant_method")
    return getattr(quantization, "quant_method", None)


def sanitize_text_only_quantization_config(quantization):
    """Remove outer-model exclusions that shadow dense text projections.

    The Qwen3.8 FP8 multimodal config contains a stale ``*.mlp.gate`` exclusion
    for every dense text layer.  When that config is transplanted onto the
    text-only model, Transformers treats ``mlp.gate`` as a parent-prefix match
    for ``mlp.gate_proj``.  The projection then remains a plain Linear and its
    FP8 scale is rejected as unexpected.  ``mlp.gate`` does not exist in the
    dense Qwen3.5 text architecture, so it is safe and necessary to remove just
    those 64 outer-model entries.
    """
    quantization = copy.deepcopy(quantization)
    if isinstance(quantization, Mapping):
        modules = quantization.get("modules_to_not_convert")
    else:
        modules = getattr(quantization, "modules_to_not_convert", None)
    if not modules:
        return quantization

    filtered = [
        module
        for module in modules
        if not (
            str(module).startswith("model.language_model.layers.")
            and str(module).endswith(".mlp.gate")
        )
    ]
    removed = len(modules) - len(filtered)
    if isinstance(quantization, Mapping):
        quantization["modules_to_not_convert"] = filtered
    else:
        quantization.modules_to_not_convert = filtered
    if removed:
        print(
            "Teacher FP8 config: removed "
            f"{removed} stale dense-router exclusions that shadow gate_proj",
            flush=True,
        )
    return quantization


def validate_fp8_teacher_load(teacher, loading_info, expected_quantization):
    """Reject a text-only load that silently discarded FP8 scale tensors."""
    unexpected = loading_info.get("unexpected_keys", [])
    ignored_scales = [key for key in unexpected if key.endswith("weight_scale_inv")]
    scale_parameters = [
        name
        for name, _ in teacher.named_parameters()
        if name.endswith("weight_scale_inv")
    ]
    print(
        "Teacher FP8 preflight: "
        f"quantization={expected_quantization}, "
        f"loaded_scale_parameters={len(scale_parameters)}, "
        f"ignored_scale_tensors={len(ignored_scales)}",
        flush=True,
    )
    if ignored_scales:
        preview = "\n".join(f"  - {key}" for key in ignored_scales[:20])
        raise RuntimeError(
            "The teacher loader ignored FP8 weight_scale_inv tensors. Its logits "
            "would be invalid, so distillation has been stopped. First keys:\n"
            f"{preview}"
        )
    if str(expected_quantization).lower().endswith("fp8") and not scale_parameters:
        raise RuntimeError(
            "The checkpoint declares FP8 quantization, but the loaded teacher has "
            "no weight_scale_inv parameters. Refusing to distill from an unverified teacher."
        )


@torch.inference_mode()
def validate_teacher_generation(teacher, tokenizer, device):
    """Require a non-empty deterministic command before using teacher logits."""
    ids = torch.tensor(
        [prompt_ids("list every file modified today", tokenizer)],
        dtype=torch.long,
        device=device,
    )
    attention_mask = torch.ones_like(ids)
    previous_cache = teacher.config.use_cache
    teacher.config.use_cache = True
    try:
        generated = teacher.generate(
            input_ids=ids,
            attention_mask=attention_mask,
            max_new_tokens=48,
            do_sample=False,
            eos_token_id=tokenizer.eos_token_id,
            pad_token_id=tokenizer.pad_token_id,
        )
    finally:
        teacher.config.use_cache = previous_cache
    continuation = generated[0, ids.shape[1] :]
    text = tokenizer.decode(continuation, skip_special_tokens=False)
    command = text.split("<|im_end|>", 1)[0].strip()
    if not command:
        raise RuntimeError(
            "The FP8 teacher produced an empty command during its generation preflight"
        )
    print(f"Teacher generation preflight: {command!r}", flush=True)


def cosine_schedule_with_warmup(optimizer, warmup_steps, total_steps):
    """Torch-native scheduler; avoids importing Transformers trainer/PEFT."""

    def multiplier(step):
        if step < warmup_steps:
            return float(step) / float(max(1, warmup_steps))
        progress = float(step - warmup_steps) / float(
            max(1, total_steps - warmup_steps)
        )
        progress = min(max(progress, 0.0), 1.0)
        return 0.5 * (1.0 + math.cos(math.pi * progress))

    return torch.optim.lr_scheduler.LambdaLR(optimizer, multiplier)


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


def tokenizer_fingerprint(tokenizer):
    """Stable digest of token strings, IDs, and generation-critical special IDs."""
    digest = hashlib.sha256()
    for token, token_id in sorted(tokenizer.get_vocab().items(), key=lambda item: item[1]):
        digest.update(str(token_id).encode("ascii"))
        digest.update(b"\0")
        digest.update(token.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
    for name in ("bos_token_id", "eos_token_id", "pad_token_id"):
        digest.update(f"{name}={getattr(tokenizer, name)}\n".encode("ascii"))
    return digest.hexdigest()


def sync_special_tokens(student, target_tokenizer):
    for name in ("bos_token_id", "eos_token_id", "pad_token_id"):
        value = getattr(target_tokenizer, name)
        setattr(student.config, name, value)
        if getattr(student, "generation_config", None) is not None:
            setattr(student.generation_config, name, value)


def transplant_student_vocabulary(
    student, source_tokenizer, target_tokenizer, target_embedding_rows
):
    """Resize and remap student embeddings/LM head to target tokenizer IDs."""
    parameters_before = sum(parameter.numel() for parameter in student.parameters())
    source_embedding_rows = student.get_input_embeddings().num_embeddings
    target_vocab = target_tokenizer.get_vocab()
    # Exact logit KL requires every teacher output row, including reserved
    # rows, so this size comes from AutoConfig rather than len(tokenizer).
    if target_embedding_rows <= max(target_vocab.values()):
        raise ValueError("Teacher config vocabulary does not cover tokenizer IDs")
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

    student.resize_token_embeddings(target_embedding_rows, mean_resizing=False)
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

    sync_special_tokens(student, target_tokenizer)

    stats = {
        "source_defined_tokens": len(source_tokenizer.get_vocab()),
        "source_embedding_rows": source_embedding_rows,
        "target_defined_tokens": len(target_vocab),
        "target_embedding_rows": target_embedding_rows,
        "exactly_remapped_tokens": len(target_ids),
        "newly_initialized_rows": target_embedding_rows - len(target_ids),
        "input_output_embeddings_were_tied": was_tied,
        "parameters_before": parameters_before,
        "parameters_after": sum(parameter.numel() for parameter in student.parameters()),
    }
    return stats, target_ids, source_ids


def save_vocabulary_bridge(
    path,
    student,
    source_tokenizer,
    target_tokenizer,
    target_ids,
    source_ids,
    stats,
    args,
):
    """Save the task-independent expanded vocabulary and output initialization."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    tied = (
        student.get_input_embeddings().weight.data_ptr()
        == student.get_output_embeddings().weight.data_ptr()
    )
    tensors = {
        "input_embeddings": student.get_input_embeddings().weight.detach().cpu().contiguous(),
        "target_token_ids": target_ids.contiguous(),
        "source_token_ids": source_ids.contiguous(),
    }
    if not tied:
        tensors["output_embeddings"] = (
            student.get_output_embeddings().weight.detach().cpu().contiguous()
        )
    output_bias = getattr(student.get_output_embeddings(), "bias", None)
    if output_bias is not None:
        tensors["output_bias"] = output_bias.detach().cpu().contiguous()

    bridge_file = path / "vocabulary_bridge.safetensors"
    temporary_file = path / "vocabulary_bridge.incomplete.safetensors"
    save_file(tensors, temporary_file)
    os.replace(temporary_file, bridge_file)
    target_tokenizer.save_pretrained(path / "target-tokenizer")
    manifest = {
        "format_version": 1,
        "source_model": args.student_model,
        "target_model": args.teacher_model,
        "source_tokenizer_sha256": tokenizer_fingerprint(source_tokenizer),
        "target_tokenizer_sha256": tokenizer_fingerprint(target_tokenizer),
        "source_vocab_rows": stats["source_embedding_rows"],
        "target_vocab_rows": stats["target_embedding_rows"],
        "embedding_width": student.get_input_embeddings().embedding_dim,
        "input_output_embeddings_tied": tied,
        "tensor_file": bridge_file.name,
        "stats": stats,
    }
    (path / "vocabulary_bridge.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Saved reusable vocabulary bridge to {path}", flush=True)


def load_vocabulary_bridge(path, student, source_tokenizer, target_tokenizer):
    """Restore a task-independent vocabulary bridge into a fresh base student."""
    path = Path(path)
    manifest = json.loads((path / "vocabulary_bridge.json").read_text(encoding="utf-8"))
    if manifest.get("format_version") != 1:
        raise ValueError(f"Unsupported vocabulary bridge format: {manifest.get('format_version')}")
    if tokenizer_fingerprint(source_tokenizer) != manifest["source_tokenizer_sha256"]:
        raise ValueError("Source tokenizer does not match the saved vocabulary bridge")
    if tokenizer_fingerprint(target_tokenizer) != manifest["target_tokenizer_sha256"]:
        raise ValueError("Teacher tokenizer does not match the saved vocabulary bridge")
    if student.get_input_embeddings().embedding_dim != manifest["embedding_width"]:
        raise ValueError("Student embedding width does not match the saved vocabulary bridge")

    student.resize_token_embeddings(manifest["target_vocab_rows"], mean_resizing=False)
    tensors = load_file(path / manifest["tensor_file"], device="cpu")
    expected_shape = (
        manifest["target_vocab_rows"],
        manifest["embedding_width"],
    )
    if tuple(tensors["input_embeddings"].shape) != expected_shape:
        raise ValueError(
            "Saved vocabulary bridge embedding shape does not match its manifest: "
            f"{tuple(tensors['input_embeddings'].shape)} != {expected_shape}"
        )
    model_is_tied = (
        student.get_input_embeddings().weight.data_ptr()
        == student.get_output_embeddings().weight.data_ptr()
    )
    if model_is_tied != manifest["input_output_embeddings_tied"]:
        raise ValueError("Student embedding tying does not match the saved vocabulary bridge")
    with torch.no_grad():
        student.get_input_embeddings().weight.copy_(
            tensors["input_embeddings"].to(student.get_input_embeddings().weight.device)
        )
        if "output_embeddings" in tensors:
            student.get_output_embeddings().weight.copy_(
                tensors["output_embeddings"].to(student.get_output_embeddings().weight.device)
            )
        output_bias = getattr(student.get_output_embeddings(), "bias", None)
        if output_bias is not None and "output_bias" in tensors:
            output_bias.copy_(tensors["output_bias"].to(output_bias.device))
    sync_special_tokens(student, target_tokenizer)
    stats = dict(manifest["stats"])
    stats["reused_from"] = str(path)
    print(f"Loaded reusable vocabulary bridge from {path}", flush=True)
    return stats


def prompt_ids(nl, tokenizer):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"Generate one Bash command: {str(nl).strip()}",
        },
    ]
    encoded = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=True,
        enable_thinking=False,
    )
    # Transformers 5 returns a BatchEncoding by default, while older releases
    # returned the input-ID list directly.
    return encoded["input_ids"] if isinstance(encoded, Mapping) else encoded


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
        encoded_prompt = prompt_ids(row["nl"], tokenizer)
        answer_ids = tokenizer.encode(
            str(row["bash"]).strip(), add_special_tokens=False
        )[: args.max_answer_tokens - 1]
        answer_ids.append(tokenizer.eos_token_id)
        if len(answer_ids) < 2:
            raise ValueError("Encountered an empty Bash answer")
        prompt_budget = args.max_length - len(answer_ids)
        if prompt_budget < 1:
            answer_ids = answer_ids[: args.max_length - 1]
            prompt_budget = 1
        # Preserve the user/assistant boundary if an unusually long request
        # must be truncated. Normal NL2SH examples fit without truncation.
        encoded_prompt = encoded_prompt[-prompt_budget:]
        input_ids = encoded_prompt + answer_ids
        labels = [-100] * len(encoded_prompt) + answer_ids
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
    progress = tqdm(
        loader,
        desc="validation",
        unit="batch",
        dynamic_ncols=True,
        leave=False,
    )
    for batch in progress:
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
    transformers_version = tuple(
        int(part) for part in transformers.__version__.split("+", 1)[0].split(".")[:2]
    )
    if transformers_version < (5, 8):
        raise RuntimeError(
            "This Qwen3.8 FP8 loader requires transformers>=5.8. Restart the "
            "Colab runtime, rerun the install cell, and confirm the printed version."
        )
    if not torch.cuda.is_available():
        raise RuntimeError("This run requires a CUDA GPU")
    if torch.cuda.get_device_capability()[0] < 8:
        raise RuntimeError("BF16 requires an Ampere-or-newer CUDA GPU")
    if not 0 <= args.distill_weight <= 1:
        raise ValueError("--distill-weight must be between 0 and 1")
    if args.max_answer_tokens < 2:
        raise ValueError("--max-answer-tokens must be at least 2")
    seed_everything(args.seed)
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.set_float32_matmul_precision("high")
    device = torch.device("cuda")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    bridge_dir = Path(args.vocabulary_bridge_dir or output_dir / "vocabulary-bridge")

    print("Loading tokenizers and the fp32 student...")
    teacher_config = AutoConfig.from_pretrained(args.teacher_model)
    teacher_text_config = causal_lm_config(teacher_config)
    # Qwen3.8 is published as a multimodal checkpoint with quantization_config
    # on the outer config. AutoModelForCausalLM extracts the nested text config;
    # carry FP8 metadata across explicitly or its scale tensors are ignored.
    outer_quantization = getattr(teacher_config, "quantization_config", None)
    if outer_quantization is not None:
        teacher_text_config.quantization_config = (
            sanitize_text_only_quantization_config(outer_quantization)
        )
    tokenizer = AutoTokenizer.from_pretrained(
        args.resume_from or args.teacher_model
    )
    tokenizer.chat_template = SHELLAI_CHAT_TEMPLATE
    if args.resume_from:
        student = AutoModelForCausalLM.from_pretrained(
            args.resume_from, dtype=torch.float32, low_cpu_mem_usage=True
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
            args.student_model, dtype=torch.float32, low_cpu_mem_usage=True
        )
        if args.reuse_vocabulary_bridge:
            transplant_stats = load_vocabulary_bridge(
                args.reuse_vocabulary_bridge,
                student,
                source_tokenizer,
                tokenizer,
            )
        else:
            transplant_stats, target_ids, source_ids = transplant_student_vocabulary(
                student,
                source_tokenizer,
                tokenizer,
                teacher_text_config.vocab_size,
            )
            if args.save_vocabulary_bridge:
                save_vocabulary_bridge(
                    bridge_dir,
                    student,
                    source_tokenizer,
                    tokenizer,
                    target_ids,
                    source_ids,
                    transplant_stats,
                    args,
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

    embedded_quantization = getattr(teacher_text_config, "quantization_config", None)
    embedded_quant_method = quantization_method(teacher_text_config)
    teacher_quantization = None
    if args.teacher_load_in_4bit and not embedded_quantization:
        teacher_quantization = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.bfloat16,
        )
    if embedded_quantization:
        teacher_format = f"its embedded {str(embedded_quant_method).upper()} format"
    elif teacher_quantization is not None:
        teacher_format = "runtime-quantized NF4"
    else:
        teacher_format = "BF16"
    print(f"Loading frozen teacher in {teacher_format}...", flush=True)
    teacher_load_kwargs = {
        "config": teacher_text_config,
        "dtype": torch.bfloat16,
        "low_cpu_mem_usage": True,
        "device_map": {"": 0},
        "output_loading_info": True,
    }
    if teacher_quantization is not None:
        teacher_load_kwargs["quantization_config"] = teacher_quantization
    teacher, teacher_loading_info = AutoModelForCausalLM.from_pretrained(
        args.teacher_model, **teacher_load_kwargs
    )
    teacher.eval()
    teacher.requires_grad_(False)
    teacher.config.use_cache = False
    if embedded_quantization:
        validate_fp8_teacher_load(
            teacher,
            teacher_loading_info,
            embedded_quant_method,
        )
    if student.config.vocab_size != causal_lm_config(teacher.config).vocab_size:
        raise RuntimeError("Vocabulary transplant failed: output sizes still differ")
    validate_teacher_generation(teacher, tokenizer, device)

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
    scheduler = cosine_schedule_with_warmup(
        optimizer,
        warmup_steps=max(1, int(total_updates * args.warmup_ratio)),
        total_steps=total_updates,
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
        progress = tqdm(
            train_loader,
            desc=f"epoch {epoch + 1}/{args.epochs}",
            unit="batch",
            dynamic_ncols=True,
        )
        for batch_index, batch in enumerate(progress, start=1):
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
                progress.set_postfix(
                    update=f"{state['global_step']}/{total_updates}",
                    loss=f"{float(loss):.4f}",
                    ce=f"{float(hard):.4f}",
                    kl=f"{float(soft):.4f}",
                    lr=f"{scheduler.get_last_lr()[0]:.2e}",
                )
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
