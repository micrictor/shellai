"""Validate the curated corpus and leakage-safe augmented DatasetDict."""

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from datasets import load_from_disk


REQUIRED_CORPUS_FIELDS = {
    "id", "nl", "bash", "category", "risk", "source", "shard", "family"
}
ALLOWED_RISKS = {"safe", "caution", "destructive"}


def text_key(value):
    return " ".join(str(value).strip().split()).casefold()


def command_key(value):
    return re.sub(r"\s+", " ", str(value).strip()).casefold()


def validate_corpus(path):
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list) or len(rows) < 10_000:
        raise ValueError("Curated corpus must be a JSON array with at least 10,000 rows")
    ids, prompts, commands = set(), set(), set()
    for index, row in enumerate(rows):
        if set(row) != REQUIRED_CORPUS_FIELDS:
            raise ValueError(f"Corpus row {index} has an unexpected schema")
        if any(not isinstance(row[field], str) or not row[field].strip() for field in row):
            raise ValueError(f"Corpus row {index} contains an empty/non-string field")
        if "\n" in row["nl"] or "\r" in row["nl"] or "\n" in row["bash"] or "\r" in row["bash"]:
            raise ValueError(f"Corpus row {index} is not single-line")
        expected_id = hashlib.sha256(
            f"{row['nl']}\0{row['bash']}".encode()
        ).hexdigest()[:16]
        if row["id"] != expected_id:
            raise ValueError(f"Corpus row {index} has a non-content-derived id")
        if row["risk"] not in ALLOWED_RISKS or row["source"] != "manual-curation":
            raise ValueError(f"Corpus row {index} has invalid provenance metadata")
        prompt, command = text_key(row["nl"]), command_key(row["bash"])
        if row["id"] in ids or prompt in prompts or command in commands:
            raise ValueError(f"Corpus row {index} duplicates an id, prompt, or command")
        ids.add(row["id"])
        prompts.add(prompt)
        commands.add(command)
    return rows


def validate_dataset(path):
    dataset = load_from_disk(str(path))
    if set(dataset) != {"train", "validation", "test"}:
        raise ValueError(f"Unexpected dataset splits: {set(dataset)}")
    prompt_sets = {
        split: {text_key(value) for value in dataset[split]["nl"]}
        for split in dataset
    }
    overlap = {
        "train_validation": len(prompt_sets["train"] & prompt_sets["validation"]),
        "train_test": len(prompt_sets["train"] & prompt_sets["test"]),
        "validation_test": len(prompt_sets["validation"] & prompt_sets["test"]),
    }
    if any(overlap.values()):
        raise ValueError(f"Normalized prompt leakage detected: {overlap}")
    family_sets = {}
    for split in ("train", "validation"):
        family_sets[split] = {
            (category, family)
            for category, family, source in zip(
                dataset[split]["category"],
                dataset[split]["family"],
                dataset[split]["source"],
            )
            if source == "manual-curation"
        }
    family_overlap = family_sets["train"] & family_sets["validation"]
    if family_overlap:
        raise ValueError(f"Curated family leakage detected: {len(family_overlap)}")
    return dataset, overlap


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--corpus", type=Path, default=Path("data/nl2sh-manual-gap-25000.json")
    )
    parser.add_argument(
        "--dataset", type=Path, default=Path("data/nl2sh-alfa-synth")
    )
    parser.add_argument(
        "--corpus-summary",
        type=Path,
        default=Path("data/nl2sh-manual-gap-25000-summary.json"),
    )
    args = parser.parse_args()
    rows = validate_corpus(args.corpus)
    corpus_hash = hashlib.sha256(args.corpus.read_bytes()).hexdigest()
    corpus_summary = json.loads(args.corpus_summary.read_text(encoding="utf-8"))
    if corpus_summary.get("corpus_sha256") != corpus_hash:
        raise ValueError("Corpus summary hash does not match the corpus artifact")
    dataset, overlap = validate_dataset(args.dataset)
    result = {
        "corpus_rows": len(rows),
        "corpus_sha256": corpus_hash,
        "categories": len(Counter(row["category"] for row in rows)),
        "families": len(Counter((row["category"], row["family"]) for row in rows)),
        "risk": dict(Counter(row["risk"] for row in rows)),
        "splits": {split: len(dataset[split]) for split in dataset},
        "prompt_overlap": overlap,
        "manual_family_overlap": 0,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
