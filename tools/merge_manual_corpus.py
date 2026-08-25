import argparse
import collections
import hashlib
import json
import os
import re
import uuid
from pathlib import Path

from datasets import load_dataset


REQUIRED_FIELDS = {"nl", "bash", "category", "risk", "source", "family"}
ALLOWED_RISKS = {"safe", "caution", "destructive"}


def normalize_nl(value):
    return " ".join(str(value).strip().split())


def normalize_bash(value):
    return str(value).strip()


def command_key(value):
    """Conservative key for spotting cosmetic command duplicates."""
    return re.sub(r"\s+", " ", normalize_bash(value)).casefold()


def load_json_array(path):
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, list):
        raise ValueError(f"{path} must contain one JSON array")
    return value


def validate_item(raw, path, index):
    missing = REQUIRED_FIELDS - set(raw)
    if missing:
        raise ValueError(f"{path}[{index}] is missing {sorted(missing)}")
    nl = normalize_nl(raw["nl"])
    bash = normalize_bash(raw["bash"])
    category = normalize_nl(raw["category"])
    risk = str(raw["risk"]).strip().lower()
    source = str(raw["source"]).strip()
    family = normalize_nl(raw.get("family", ""))
    if not nl or not bash or not category or not family:
        raise ValueError(f"{path}[{index}] contains an empty required value")
    if "\n" in bash or "\r" in bash:
        raise ValueError(f"{path}[{index}] Bash command must be one line")
    if risk not in ALLOWED_RISKS:
        raise ValueError(f"{path}[{index}] has invalid risk: {risk}")
    if source != "manual-curation":
        raise ValueError(f"{path}[{index}] has invalid source: {source}")
    identifier = hashlib.sha256(f"{nl}\0{bash}".encode()).hexdigest()[:16]
    return {
        "id": identifier,
        "nl": nl,
        "bash": bash,
        "category": category,
        "risk": risk,
        "source": source,
        "shard": path.stem,
        "family": family,
    }


def command_head(command):
    match = re.match(r"(?:sudo\s+|env\s+)?([^\s|;&()]+)", command)
    return match.group(1) if match else "<compound>"


def main():
    parser = argparse.ArgumentParser(
        description="Merge manually curated NL-to-Bash shards with novelty checks."
    )
    parser.add_argument("shards", nargs="+", type=Path)
    parser.add_argument(
        "--output", type=Path, default=Path("data/nl2sh-manual-gap-10000.json")
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=Path("data/nl2sh-manual-gap-10000-summary.json"),
    )
    parser.add_argument("--minimum", type=int, default=10_000)
    parser.add_argument("--max-per-category", type=int, default=250)
    parser.add_argument("--max-per-command-head", type=int, default=1000)
    parser.add_argument(
        "--exclude-corpus",
        action="append",
        type=Path,
        default=[],
        help="Additional JSON-array corpus whose prompts and commands must remain novel.",
    )
    args = parser.parse_args()

    base_train = load_dataset(
        "westenfelder/NL2SH-ALFA", "train", split="train"
    )
    official_test = load_dataset(
        "westenfelder/NL2SH-ALFA", "test", split="train"
    )
    nl2sh_prompts = {
        normalize_nl(value).casefold()
        for value in list(base_train["nl"]) + list(official_test["nl"])
    }
    nl2sh_commands = {
        command_key(value)
        for value in list(base_train["bash"]) + list(official_test["bash"])
    }
    if "bash2" in official_test.column_names:
        nl2sh_commands.update(
            command_key(value)
            for value in official_test["bash2"]
            if value
        )

    excluded_prompts = set()
    excluded_commands = set()
    exclusion_counts = {}
    for exclusion_path in args.exclude_corpus:
        exclusion_rows = load_json_array(exclusion_path)
        exclusion_counts[exclusion_path.name] = len(exclusion_rows)
        for row in exclusion_rows:
            if not isinstance(row, dict) or not row.get("nl") or not row.get("bash"):
                raise ValueError(f"Invalid exclusion row in {exclusion_path}")
            excluded_prompts.add(normalize_nl(row["nl"]).casefold())
            excluded_commands.add(command_key(row["bash"]))

    accepted = []
    seen_prompts = set()
    seen_pairs = set()
    seen_commands = set()
    rejection_counts = collections.Counter()
    input_counts = {}
    for shard in args.shards:
        raw_items = load_json_array(shard)
        input_counts[shard.name] = len(raw_items)
        for index, raw in enumerate(raw_items):
            item = validate_item(raw, shard, index)
            if re.search(r"(?:^|\s)#\s", item["bash"]):
                rejection_counts["comment_only_context"] += 1
                continue
            prompt_key = item["nl"].casefold()
            pair_key = (prompt_key, item["bash"])
            if prompt_key in nl2sh_prompts:
                rejection_counts["prompt_already_in_nl2sh"] += 1
                continue
            bash_key = command_key(item["bash"])
            if bash_key in nl2sh_commands:
                rejection_counts["command_already_in_nl2sh"] += 1
                continue
            if prompt_key in excluded_prompts:
                rejection_counts["prompt_already_in_excluded_corpus"] += 1
                continue
            if bash_key in excluded_commands:
                rejection_counts["command_already_in_excluded_corpus"] += 1
                continue
            if prompt_key in seen_prompts:
                rejection_counts["duplicate_manual_prompt"] += 1
                continue
            if pair_key in seen_pairs:
                rejection_counts["duplicate_manual_pair"] += 1
                continue
            if bash_key in seen_commands:
                rejection_counts["duplicate_manual_command"] += 1
                continue
            seen_prompts.add(prompt_key)
            seen_pairs.add(pair_key)
            seen_commands.add(bash_key)
            accepted.append(item)

    # Deterministically sample across the combined shards before enforcing
    # diversity caps, rather than letting shard or category ordering win.
    accepted.sort(key=lambda item: item["id"])
    diverse = []
    category_counts = collections.Counter()
    command_counts = collections.Counter()
    for item in accepted:
        head = command_head(item["bash"])
        if category_counts[item["category"]] >= args.max_per_category:
            rejection_counts["category_diversity_cap"] += 1
            continue
        if command_counts[head] >= args.max_per_command_head:
            rejection_counts["command_head_diversity_cap"] += 1
            continue
        category_counts[item["category"]] += 1
        command_counts[head] += 1
        diverse.append(item)
    accepted = sorted(diverse, key=lambda item: (item["category"], item["id"]))
    if len(accepted) < args.minimum:
        raise RuntimeError(
            f"Only {len(accepted):,} novel examples remain; need {args.minimum:,}. "
            f"Rejections: {dict(rejection_counts)}"
        )

    corpus_text = json.dumps(accepted, indent=2, ensure_ascii=False) + "\n"
    summary = {
        "output": str(args.output),
        "corpus_sha256": hashlib.sha256(corpus_text.encode("utf-8")).hexdigest(),
        "accepted_examples": len(accepted),
        "input_examples": input_counts,
        "exclusion_examples": exclusion_counts,
        "rejections": dict(rejection_counts),
        "categories": dict(collections.Counter(x["category"] for x in accepted)),
        "risk": dict(collections.Counter(x["risk"] for x in accepted)),
        "top_command_heads": dict(
            collections.Counter(command_head(x["bash"]) for x in accepted).most_common(100)
        ),
        "novelty_guarantees": {
            "exact_prompt_overlap_with_nl2sh": 0,
            "exact_command_overlap_with_nl2sh": 0,
            "exact_prompt_overlap_with_excluded_corpora": 0,
            "exact_command_overlap_with_excluded_corpora": 0,
            "duplicate_manual_prompts": 0,
            "duplicate_manual_pairs": 0,
            "duplicate_manual_commands": 0,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    pending = []
    try:
        summary_text = json.dumps(summary, indent=2, ensure_ascii=False) + "\n"
        for path, value in (
            (args.output, corpus_text),
            (args.summary, summary_text),
        ):
            temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
            with temp_path.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            pending.append((temp_path, path))
        for temp_path, path in pending:
            os.replace(temp_path, path)
    finally:
        for temp_path, _ in pending:
            if temp_path.exists():
                temp_path.unlink()
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
