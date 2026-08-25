import argparse
import csv
import json
import re
import time
from pathlib import Path

import numpy as np
import torch
from datasets import load_from_disk
from transformers import (
    AutoModelForCausalLM,
    AutoModelForSeq2SeqLM,
    AutoTokenizer,
)

from models.seq2seq_lstm import (
    AttentionDecoderLSTM,
    EncoderLSTM,
    Seq2SeqAttentionLSTM,
)
from models.seq2seq_rnn import (
    AttentionDecoderRNN,
    EncoderRNN,
    Seq2SeqAttention,
)


def test_bash_syntax(command):
    """Lightweight structural check; it does not execute generated commands."""
    command = command.strip()
    if not command:
        return False
    return (
        command.count('"') % 2 == 0
        and command.count("'") % 2 == 0
        and command.count("(") == command.count(")")
        and command.count("[") == command.count("]")
    )


def compute_token_f1(reference, candidate):
    reference_tokens = reference.strip().split()
    candidate_tokens = candidate.strip().split()
    if not reference_tokens or not candidate_tokens:
        return 0.0
    remaining = list(reference_tokens)
    matches = 0
    for token in candidate_tokens:
        if token in remaining:
            matches += 1
            remaining.remove(token)
    if not matches:
        return 0.0
    precision = matches / len(candidate_tokens)
    recall = matches / len(reference_tokens)
    return 2 * precision * recall / (precision + recall)


def references_for(sample):
    return sample.get("references") or [sample["bash"]]


def model_files_in(directory):
    patterns = (
        "model*.safetensors",
        "pytorch_model*.bin",
    )
    return [
        path
        for pattern in patterns
        for path in directory.glob(pattern)
        if path.is_file()
    ]


def discover_custom_checkpoints(checkpoints_dir):
    run_directories = {
        path.parent
        for filename in ("best_model.pt", "seq2seq_model.pt")
        for path in checkpoints_dir.rglob(filename)
    }
    checkpoints = []
    for directory in sorted(run_directories):
        best = directory / "best_model.pt"
        final = directory / "seq2seq_model.pt"
        checkpoints.append(best if best.is_file() else final)
    return checkpoints


def discover_huggingface_models(checkpoints_dir):
    candidates = []
    for config_path in checkpoints_dir.rglob("config.json"):
        directory = config_path.parent
        if not model_files_in(directory):
            continue
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if config.get("is_encoder_decoder") is True:
            candidates.append(directory)

    # A Trainer output directory contains the selected final model as well as
    # checkpoint-N children. Evaluate the final model once, not every epoch copy.
    candidate_set = set(candidates)
    final_models = []
    for directory in candidates:
        if directory.name.startswith("checkpoint-") and directory.parent in candidate_set:
            continue
        final_models.append(directory)
    return sorted(set(final_models))


def discover_causal_models(checkpoints_dir):
    candidates = []
    for config_path in checkpoints_dir.rglob("config.json"):
        directory = config_path.parent
        if not model_files_in(directory):
            continue
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        architectures = config.get("architectures") or []
        if (
            config.get("is_encoder_decoder") is False
            or any(name.endswith("ForCausalLM") for name in architectures)
        ):
            candidates.append(directory)

    candidate_set = set(candidates)
    return sorted(
        {
            directory
            for directory in candidates
            if not (
                directory.name.startswith("checkpoint-")
                and directory.parent in candidate_set
            )
        }
    )


def synchronize(device):
    if device.type == "cuda":
        torch.cuda.synchronize()


def summarize_predictions(
    predictions,
    samples,
    latencies,
    model_name,
    parameter_count,
    model_size_bytes,
    model_path,
):
    exact_matches = 0
    syntax_matches = 0
    token_f1_scores = []
    for prediction, sample in zip(predictions, samples):
        references = [reference.strip() for reference in references_for(sample)]
        exact_matches += prediction in references
        syntax_matches += test_bash_syntax(prediction)
        token_f1_scores.append(
            max(compute_token_f1(reference, prediction) for reference in references)
        )

    count = len(samples)
    return {
        "model": model_name,
        "examples": count,
        "exact_match_pct": round(100 * exact_matches / count, 2),
        "syntax_valid_pct": round(100 * syntax_matches / count, 2),
        "token_f1": round(float(np.mean(token_f1_scores)), 4),
        "latency_ms": round(float(np.mean(latencies)), 2),
        "parameters_m": round(parameter_count / 1e6, 2),
        "size_mb": round(model_size_bytes / (1024**2), 2),
        "path": str(model_path),
    }


def evaluate_huggingface_model(model_path, test_samples, max_new_tokens):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_path).to(device)
    model.eval()
    prefix = "translate natural language to bash: "
    predictions = []
    latencies = []

    print(f"\nEvaluating Hugging Face model: {model_path}")
    with torch.inference_mode():
        for index, sample in enumerate(test_samples, start=1):
            inputs = tokenizer(
                prefix + sample["nl"],
                return_tensors="pt",
                truncation=True,
                max_length=128,
            ).to(device)
            synchronize(device)
            started_at = time.perf_counter()
            output = model.generate(**inputs, max_new_tokens=max_new_tokens)
            synchronize(device)
            latencies.append((time.perf_counter() - started_at) * 1000)
            predictions.append(
                tokenizer.decode(output[0], skip_special_tokens=True).strip()
            )
            if index % 50 == 0 or index == len(test_samples):
                print(f"  {index}/{len(test_samples)} examples", flush=True)

    result = summarize_predictions(
        predictions=predictions,
        samples=test_samples,
        latencies=latencies,
        model_name=model_path.name,
        parameter_count=sum(parameter.numel() for parameter in model.parameters()),
        model_size_bytes=sum(path.stat().st_size for path in model_files_in(model_path)),
        model_path=model_path,
    )
    del model
    if device.type == "cuda":
        torch.cuda.empty_cache()
    return result


def extract_bash_command(response):
    response = response.strip()
    fenced = re.search(
        r"```(?:bash|sh)?\s*(.*?)```",
        response,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if fenced:
        return fenced.group(1).strip()
    lines = [line.strip() for line in response.splitlines() if line.strip()]
    if not lines:
        return ""
    command = lines[0]
    return command[2:].strip() if command.startswith("$ ") else command


def evaluate_causal_model(model_path, test_samples, max_new_tokens):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForCausalLM.from_pretrained(model_path).to(device)
    model.eval()
    system_prompt = (
        "You are a helpful assistant that translates natural language to "
        "bash commands."
    )
    predictions = []
    latencies = []

    display_name = (
        "gemma-3-270m-it-ft-bash"
        if model_path.name == "checkpoints"
        else model_path.name
    )
    print(f"\nEvaluating causal model: {display_name} ({model_path})")
    with torch.inference_mode():
        for index, sample in enumerate(test_samples, start=1):
            messages = [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": f"Generate single Bash command: {sample['nl']}",
                },
            ]
            inputs = tokenizer.apply_chat_template(
                messages,
                add_generation_prompt=True,
                tokenize=True,
                return_tensors="pt",
                return_dict=True,
            ).to(device)
            input_length = inputs["input_ids"].shape[1]
            synchronize(device)
            started_at = time.perf_counter()
            output = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,
            )
            synchronize(device)
            latencies.append((time.perf_counter() - started_at) * 1000)
            response = tokenizer.decode(
                output[0, input_length:],
                skip_special_tokens=True,
            )
            predictions.append(extract_bash_command(response))
            if index % 50 == 0 or index == len(test_samples):
                print(f"  {index}/{len(test_samples)} examples", flush=True)

    result = summarize_predictions(
        predictions=predictions,
        samples=test_samples,
        latencies=latencies,
        model_name=display_name,
        parameter_count=sum(parameter.numel() for parameter in model.parameters()),
        model_size_bytes=sum(path.stat().st_size for path in model_files_in(model_path)),
        model_path=model_path,
    )
    del model
    if device.type == "cuda":
        torch.cuda.empty_cache()
    return result


def evaluate_custom_model(checkpoint_path, test_samples, max_new_tokens):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    checkpoint = torch.load(
        checkpoint_path, map_location="cpu", weights_only=False
    )
    tokenizer = AutoTokenizer.from_pretrained(checkpoint["tokenizer_name"])
    architecture = checkpoint.get("architecture", "gru")
    pad_idx = checkpoint.get("pad_idx", tokenizer.pad_token_id)
    encoder_class = EncoderLSTM if architecture == "lstm" else EncoderRNN
    decoder_class = (
        AttentionDecoderLSTM if architecture == "lstm" else AttentionDecoderRNN
    )
    model_class = (
        Seq2SeqAttentionLSTM if architecture == "lstm" else Seq2SeqAttention
    )
    encoder = encoder_class(
        checkpoint["vocab_size"],
        checkpoint["embed_dim"],
        checkpoint["hidden_dim"],
        padding_idx=pad_idx,
    )
    decoder = decoder_class(
        checkpoint["vocab_size"],
        checkpoint["embed_dim"],
        checkpoint["hidden_dim"],
        padding_idx=pad_idx,
    )
    if (
        architecture == "lstm"
        or checkpoint.get("model_variant") == "seq2seq-transfer"
    ):
        decoder.embedding = encoder.embedding
    model = model_class(
        encoder,
        decoder,
        pad_idx=pad_idx,
        sos_idx=checkpoint.get("sos_idx", tokenizer.pad_token_id),
        eos_idx=checkpoint.get("eos_idx", tokenizer.eos_token_id),
    ).to(device)
    incompatible = model.load_state_dict(
        checkpoint["model_state_dict"], strict=False
    )
    legacy_scale_key = "decoder.output_logit_scale"
    if incompatible.missing_keys == [legacy_scale_key]:
        # LSTM checkpoints created before logit calibration used an implicit
        # scale of 1.0. Preserve their original inference behavior.
        model.decoder.output_logit_scale.data.zero_()
    elif incompatible.missing_keys or incompatible.unexpected_keys:
        raise RuntimeError(
            f"Incompatible checkpoint keys: missing={incompatible.missing_keys}, "
            f"unexpected={incompatible.unexpected_keys}"
        )
    model.eval()

    variant = checkpoint.get("model_variant", checkpoint_path.parent.name)
    model_name = f"{architecture.upper()} {variant.removeprefix('seq2seq-')}"
    predictions = []
    latencies = []
    max_source_length = checkpoint.get("max_source_length", 128)

    print(f"\nEvaluating custom model: {model_name} ({checkpoint_path})")
    with torch.inference_mode():
        for index, sample in enumerate(test_samples, start=1):
            inputs = tokenizer(
                sample["nl"],
                return_tensors="pt",
                max_length=max_source_length,
                padding="max_length",
                truncation=True,
            )["input_ids"].to(device)
            synchronize(device)
            started_at = time.perf_counter()
            decoded = model(inputs, trg=None, max_len=max_new_tokens)
            synchronize(device)
            latencies.append((time.perf_counter() - started_at) * 1000)
            predictions.append(
                tokenizer.decode(decoded[0], skip_special_tokens=True).strip()
            )
            if index % 50 == 0 or index == len(test_samples):
                print(f"  {index}/{len(test_samples)} examples", flush=True)

    result = summarize_predictions(
        predictions=predictions,
        samples=test_samples,
        latencies=latencies,
        model_name=model_name,
        parameter_count=checkpoint.get(
            "params", sum(parameter.numel() for parameter in model.parameters())
        ),
        model_size_bytes=checkpoint_path.stat().st_size,
        model_path=checkpoint_path,
    )
    del model, checkpoint
    if device.type == "cuda":
        torch.cuda.empty_cache()
    return result


def format_table(results):
    columns = [
        ("Model", "model"),
        ("N", "examples"),
        ("Exact", "exact_match_pct"),
        ("Syntax", "syntax_valid_pct"),
        ("Token F1", "token_f1"),
        ("Latency", "latency_ms"),
        ("Params", "parameters_m"),
        ("Size", "size_mb"),
    ]
    formatted_rows = []
    for result in results:
        formatted_rows.append(
            {
                "model": result["model"],
                "examples": str(result["examples"]),
                "exact_match_pct": f'{result["exact_match_pct"]:.2f}%',
                "syntax_valid_pct": f'{result["syntax_valid_pct"]:.2f}%',
                "token_f1": f'{result["token_f1"]:.4f}',
                "latency_ms": f'{result["latency_ms"]:.2f} ms',
                "parameters_m": f'{result["parameters_m"]:.2f}M',
                "size_mb": f'{result["size_mb"]:.2f} MB',
            }
        )
    widths = {
        key: max(len(title), *(len(row[key]) for row in formatted_rows))
        for title, key in columns
    }
    header = " | ".join(title.ljust(widths[key]) for title, key in columns)
    separator = "-+-".join("-" * widths[key] for _, key in columns)
    lines = [header, separator]
    for row in formatted_rows:
        cells = []
        for index, (_, key) in enumerate(columns):
            value = row[key]
            cells.append(
                value.ljust(widths[key]) if index == 0 else value.rjust(widths[key])
            )
        lines.append(" | ".join(cells))
    return "\n".join(lines)


def write_results(results, failures, output_json):
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(
            {"results": results, "failures": failures},
            indent=2,
        ),
        encoding="utf-8",
    )
    output_csv = output_json.with_suffix(".csv")
    if results:
        with output_csv.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    return output_csv


def run_all_evaluations(
    dataset_dir,
    checkpoints_dir,
    output_json,
    max_eval=None,
    max_new_tokens=64,
):
    dataset = load_from_disk(str(dataset_dir))
    if "test" not in dataset:
        raise ValueError(f"No test split in dataset: {dataset_dir}")
    test_samples = dataset["test"].to_list()
    if max_eval is not None:
        test_samples = test_samples[:max_eval]
    if not test_samples:
        raise ValueError("The selected evaluation set is empty.")

    custom_checkpoints = discover_custom_checkpoints(checkpoints_dir)
    huggingface_models = discover_huggingface_models(checkpoints_dir)
    causal_models = discover_causal_models(checkpoints_dir)
    print(
        f"Discovered {len(custom_checkpoints)} custom checkpoint(s) and "
        f"{len(huggingface_models)} Hugging Face seq2seq model(s), plus "
        f"{len(causal_models)} causal model(s)."
    )
    results = []
    failures = []

    for checkpoint_path in custom_checkpoints:
        try:
            results.append(
                evaluate_custom_model(
                    checkpoint_path, test_samples, max_new_tokens
                )
            )
        except Exception as error:
            failures.append(
                {"path": str(checkpoint_path), "error": str(error)}
            )
            print(f"  FAILED: {checkpoint_path}: {error}")
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

    for model_path in huggingface_models:
        try:
            results.append(
                evaluate_huggingface_model(
                    model_path, test_samples, max_new_tokens
                )
            )
        except Exception as error:
            failures.append({"path": str(model_path), "error": str(error)})
            print(f"  FAILED: {model_path}: {error}")
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

    for model_path in causal_models:
        try:
            results.append(
                evaluate_causal_model(
                    model_path, test_samples, max_new_tokens
                )
            )
        except Exception as error:
            failures.append({"path": str(model_path), "error": str(error)})
            print(f"  FAILED: {model_path}: {error}")
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

    results.sort(key=lambda item: (-item["exact_match_pct"], -item["token_f1"]))
    print("\nMODEL EVALUATION RESULTS")
    print("=" * 120)
    if results:
        print(format_table(results))
    else:
        print("No completed compatible models were successfully evaluated.")
    print("=" * 120)

    output_csv = write_results(results, failures, output_json)
    print(f"JSON results: {output_json.resolve()}")
    if results:
        print(f"CSV results:  {output_csv.resolve()}")
    if failures:
        print(f"\n{len(failures)} model(s) failed; details are in the JSON output.")
    return results, failures


def parse_args():
    parser = argparse.ArgumentParser(
        description="Discover and evaluate every completed NL-to-Bash model."
    )
    parser.add_argument("--dataset-dir", default="data/nl2sh-alfa-synth")
    parser.add_argument("--checkpoints-dir", default="checkpoints")
    parser.add_argument(
        "--output-json", default="data/benchmark_results.json"
    )
    parser.add_argument(
        "--max-eval",
        type=int,
        help="Evaluate only the first N official test examples (default: all).",
    )
    parser.add_argument("--max-new-tokens", type=int, default=64)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_all_evaluations(
        dataset_dir=Path(args.dataset_dir),
        checkpoints_dir=Path(args.checkpoints_dir),
        output_json=Path(args.output_json),
        max_eval=args.max_eval,
        max_new_tokens=args.max_new_tokens,
    )
