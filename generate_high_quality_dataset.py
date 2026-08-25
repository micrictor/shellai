import argparse
import hashlib
import json
import os
import random
import shutil
import uuid
from collections import Counter
from pathlib import Path

from datasets import Dataset, DatasetDict, DatasetInfo, load_dataset


DATASET_DESCRIPTION = """NL2SH-ALFA training data augmented with a manually
curated, gap-focused NL-to-Bash corpus. Curated examples carry category, risk,
and command-family metadata. Related curated families are held entirely in
either train or validation, and the official manually verified NL2SH-ALFA test
configuration remains isolated as the test split."""

ALLOWED_RISKS = {"safe", "caution", "destructive"}
DATASET_MARKERS = {"dataset_dict.json", "summary.json"}


def clean_nl(value):
    return " ".join(str(value).strip().split())


def clean_bash(value):
    return str(value).strip()


def make_record(
    nl,
    bash,
    source,
    category,
    risk,
    family,
    references=None,
):
    nl = clean_nl(nl)
    bash = clean_bash(bash)
    if not nl or not bash:
        raise ValueError("Dataset records require non-empty nl and bash values")
    refs = [clean_bash(ref) for ref in (references or [bash]) if clean_bash(ref)]
    return {
        "nl": nl,
        "bash": bash,
        "references": list(dict.fromkeys(refs)),
        "source": source,
        "category": category,
        "risk": risk,
        "family": family,
    }


def load_manual_corpus(path, allowed_risks=None):
    path = Path(path)
    with path.open("r", encoding="utf-8") as handle:
        rows = json.load(handle)
    if not isinstance(rows, list):
        raise ValueError(f"Manual corpus must be a JSON array: {path}")

    records = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{path}[{index}] must be a JSON object")
        required = {"nl", "bash", "category", "risk", "source", "family"}
        missing = required - set(row)
        if missing:
            raise ValueError(f"{path}[{index}] missing fields: {sorted(missing)}")
        nl = clean_nl(row["nl"])
        bash = clean_bash(row["bash"])
        category = clean_nl(row["category"])
        family = clean_nl(row["family"])
        risk = str(row["risk"]).strip().lower()
        source = str(row["source"]).strip()
        if not nl or not bash or not category or not family:
            raise ValueError(f"{path}[{index}] contains an empty required value")
        if "\n" in bash or "\r" in bash:
            raise ValueError(f"{path}[{index}] Bash command must be one line")
        if source != "manual-curation":
            raise ValueError(f"{path}[{index}] has invalid source: {source}")
        if risk not in ALLOWED_RISKS:
            raise ValueError(f"{path}[{index}] has invalid risk: {risk}")
        if allowed_risks is not None and risk not in allowed_risks:
            continue
        records.append(
            make_record(
                nl,
                bash,
                "manual-curation",
                category,
                risk,
                family,
            )
        )
    return records


def deduplicate(records, excluded_prompts=None):
    excluded_prompts = excluded_prompts or set()
    unique = {}
    for item in records:
        prompt_key = item["nl"].casefold()
        if prompt_key in excluded_prompts:
            continue
        unique.setdefault((prompt_key, item["bash"]), item)
    return list(unique.values())


def connected_groups(records):
    """Group the transitive closure of shared prompts and curated families."""
    parents = list(range(len(records)))

    def find(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left, right):
        left, right = find(left), find(right)
        if left != right:
            parents[right] = left

    owner = {}
    for index, item in enumerate(records):
        keys = [f"prompt:{item['nl'].casefold()}"]
        if item["source"] == "manual-curation":
            keys.append(f"family:{item['category']}:{item['family']}")
        for key in keys:
            if key in owner:
                union(index, owner[key])
            else:
                owner[key] = index

    groups = {}
    for index, item in enumerate(records):
        groups.setdefault(find(index), []).append(item)
    return groups


def sample_manual_families(records, limit, seed):
    if limit is None or len(records) <= limit:
        return records
    groups = {}
    for item in records:
        key = f"{item['category']}:{item['family']}"
        groups.setdefault(key, []).append(item)
    ordered = sorted(
        groups,
        key=lambda key: hashlib.sha256(f"manual-limit:{seed}:{key}".encode()).hexdigest(),
    )
    selected = []
    for key in ordered:
        family = groups[key]
        if len(selected) + len(family) <= limit:
            selected.extend(family)
    if not selected and ordered:
        selected.extend(groups[ordered[0]])
    return selected


def split_grouped(records, validation_fraction, seed):
    groups = connected_groups(records)

    ordered = sorted(
        groups,
        key=lambda group: hashlib.sha256(
            f"{seed}:{min(item['nl'] for item in groups[group])}".encode()
        ).hexdigest(),
    )
    target = round(len(records) * validation_fraction)
    validation_groups = set()
    size = 0
    for group in ordered:
        if size >= target:
            break
        validation_groups.add(group)
        size += len(groups[group])

    train, validation = [], []
    for group, items in groups.items():
        (validation if group in validation_groups else train).extend(items)
    return train, validation


def build_dataset(manual_corpus, validation_fraction=0.1, seed=42, manual_limit=None, allowed_risks=None):
    if not 0 < validation_fraction < 1:
        raise ValueError("--validation-fraction must be between 0 and 1")
    print("Loading NL2SH-ALFA training and official test configurations...")
    base_train = load_dataset("westenfelder/NL2SH-ALFA", "train", split="train")
    official_test = load_dataset("westenfelder/NL2SH-ALFA", "test", split="train")

    test_records = []
    for index, sample in enumerate(official_test):
        references = [sample["bash"]]
        if sample.get("bash2"):
            references.append(sample["bash2"])
        test_records.append(
            make_record(
                sample["nl"], sample["bash"], "nl2sh-alfa-official-test",
                "official-benchmark", "unlabeled", f"official-{index}", references,
            )
        )
    test_prompts = {item["nl"].casefold() for item in test_records}

    base_records = [
        make_record(
            sample["nl"], sample["bash"], "nl2sh-alfa-train",
            "nl2sh-alfa", "unlabeled", f"source-prompt:{clean_nl(sample['nl']).casefold()}",
        )
        for sample in base_train
    ]
    manual_records = load_manual_corpus(manual_corpus, allowed_risks=allowed_risks)
    raw_records = base_records + manual_records
    base_unique = deduplicate(base_records, test_prompts)
    manual_unique = deduplicate(manual_records, test_prompts)
    base_pairs = {(item["nl"].casefold(), item["bash"]) for item in base_unique}
    manual_unique = [
        item
        for item in manual_unique
        if (item["nl"].casefold(), item["bash"]) not in base_pairs
    ]
    manual_rows_before_limit = len(manual_unique)
    manual_selected = sample_manual_families(manual_unique, manual_limit, seed)
    augmented_records = base_unique + manual_selected
    train_records, validation_records = split_grouped(
        augmented_records, validation_fraction, seed
    )
    rng = random.Random(seed)
    rng.shuffle(train_records)
    rng.shuffle(validation_records)

    info = DatasetInfo(description=DATASET_DESCRIPTION, license="mit")
    dataset = DatasetDict(
        {
            "train": Dataset.from_list(train_records, info=info.copy()),
            "validation": Dataset.from_list(validation_records, info=info.copy()),
            "test": Dataset.from_list(test_records, info=info.copy()),
        }
    )
    stats = {
        "base_train_rows": len(base_train),
        "manual_corpus_rows": len(manual_records),
        "manual_rows_selected": len(manual_selected),
        "duplicate_or_test_rows_removed": (
            len(raw_records) - len(base_unique) - manual_rows_before_limit
        ),
        "manual_rows_omitted_by_limit": manual_rows_before_limit - len(manual_selected),
        "manual_categories": dict(Counter(x["category"] for x in manual_selected)),
        "manual_risk": dict(Counter(x["risk"] for x in manual_selected)),
    }
    return dataset, stats


def save_dataset(dataset, output_dir, build_stats):
    output_dir = Path(output_dir).resolve()
    working_dir = Path.cwd().resolve()
    if output_dir in {working_dir, output_dir.parent}:
        raise ValueError(f"Refusing unsafe dataset output path: {output_dir}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = output_dir.with_name(f".{output_dir.name}.staging.{uuid.uuid4().hex}")
    backup = output_dir.with_name(f"{output_dir.name}.backup")

    if backup.exists() and not output_dir.exists():
        backup.rename(output_dir)
    elif backup.exists():
        raise RuntimeError(
            f"Both output and recovery backup exist; inspect them before retrying: "
            f"{output_dir}, {backup}"
        )
    if output_dir.exists():
        if not output_dir.is_dir():
            raise ValueError(f"Dataset output exists and is not a directory: {output_dir}")
        present = {path.name for path in output_dir.iterdir()}
        if not DATASET_MARKERS.issubset(present):
            raise ValueError(
                f"Refusing to replace a directory without dataset markers "
                f"{sorted(DATASET_MARKERS)}: {output_dir}"
            )

    try:
        dataset.save_to_disk(str(staging))
        for split, split_dataset in dataset.items():
            split_dataset.to_json(
                str(staging / f"{split}.json"),
                orient="records", lines=True, force_ascii=False,
            )
        summary = {
            "dataset_name": output_dir.name,
            "splits": {name: len(split) for name, split in dataset.items()},
            **build_stats,
            "sample_examples": dataset["train"].select(
                range(min(10, len(dataset["train"])))
            ).to_list(),
        }
        summary_text = json.dumps(summary, indent=2, ensure_ascii=False) + "\n"
        (staging / "summary.json").write_text(summary_text, encoding="utf-8")
        (staging / "build_manifest.json").write_text(
            json.dumps({"format": "nl2sh-augmented-dataset", "version": 1}),
            encoding="utf-8",
        )
        if output_dir.exists():
            output_dir.rename(backup)
        staging.rename(output_dir)
        if backup.exists():
            shutil.rmtree(backup)
        # Keep the historical sibling summary in sync for older tooling that
        # still reads data/<dataset-name>-summary.json.
        sibling_summary = output_dir.with_name(f"{output_dir.name}-summary.json")
        pending_summary = sibling_summary.with_name(
            f".{sibling_summary.name}.{uuid.uuid4().hex}.tmp"
        )
        try:
            pending_summary.write_text(summary_text, encoding="utf-8")
            os.replace(pending_summary, sibling_summary)
        finally:
            if pending_summary.exists():
                pending_summary.unlink()
    except Exception:
        if backup.exists() and not output_dir.exists():
            backup.rename(output_dir)
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return output_dir


def hub_token(env_file):
    token = os.environ.get("HF_TOKEN")
    path = Path(env_file)
    if token or not path.is_file():
        return token
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            if key.strip() == "HF_TOKEN":
                return value.strip().strip("\"'")
    return None


def parse_args():
    parser = argparse.ArgumentParser(
        description="Build NL2SH-ALFA plus the manually curated gap corpus."
    )
    parser.add_argument(
        "--manual-corpus", default="data/nl2sh-manual-gap-25000.json"
    )
    parser.add_argument("--manual-limit", type=int)
    parser.add_argument("--validation-fraction", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", default="data/nl2sh-alfa-synth")
    parser.add_argument(
        "--max-risk", choices=["safe", "caution", "destructive"],
        default="destructive",
        help="Highest curated-command risk to include.",
    )
    parser.add_argument("--push-to-hub", action="store_true")
    parser.add_argument("--hub-repo")
    parser.add_argument("--private", action="store_true")
    parser.add_argument("--env-file", default=".env")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.push_to_hub and not args.hub_repo:
        raise SystemExit("--hub-repo is required with --push-to-hub")
    if args.manual_limit is not None and args.manual_limit < 1:
        raise SystemExit("--manual-limit must be a positive integer")
    risk_order = ["safe", "caution", "destructive"]
    allowed_risks = set(risk_order[: risk_order.index(args.max_risk) + 1])
    dataset, stats = build_dataset(
        args.manual_corpus,
        validation_fraction=args.validation_fraction,
        seed=args.seed,
        manual_limit=args.manual_limit,
        allowed_risks=allowed_risks,
    )
    output_dir = save_dataset(dataset, args.output_dir, stats)
    print(f"Saved dataset to '{output_dir}'")
    print("Split sizes:", {name: len(split) for name, split in dataset.items()})
    if args.push_to_hub:
        dataset.push_to_hub(
            args.hub_repo, private=args.private, token=hub_token(args.env_file)
        )
        print(f"Published https://huggingface.co/datasets/{args.hub_repo}")
    else:
        print("Hub publishing skipped (pass --push-to-hub --hub-repo USER/REPO).")


if __name__ == "__main__":
    main()
