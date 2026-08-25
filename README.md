# NL-to-Bash training experiments

This project compares:

- `google/flan-t5-small` fine-tuned for natural-language-to-Bash generation;
- a GRU attention seq2seq model trained from scratch;
- the same GRU architecture initialized with FLAN-T5 token embeddings;
- bidirectional LSTM attention seq2seq scratch and transfer variants.

The generated Hugging Face `DatasetDict` contains:

- `train`: NL2SH-ALFA training data plus the gap-focused curated corpus;
- `validation`: a held-out split used for checkpoint selection (synthetic
  operation families and duplicate prompts stay entirely in one split);
- `test`: the official manually verified NL2SH-ALFA test configuration, kept
  out of training and validation.

## 1. Environment

From PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Python 3.10-3.12 is recommended for the pinned major versions in this project.

## 2. Curated corpus and augmented dataset

The default `data/nl2sh-manual-gap-25000.json` contains 25,920 unique
NL-to-Bash pairs across 327 categories and 1,142 operation families. It combines
two independently audited manual corpora. The first emphasizes Kubernetes and
Helm, Terraform/OpenTofu, cloud CLIs, observability, supply-chain security,
advanced Git/build/data tooling, namespaces/cgroups, networking, storage,
cryptography, and robust Bash patterns. The second adds 14,255 examples focused
on package and host administration, firewalls, storage systems, messaging,
GitOps and Kubernetes ecosystem tools, databases and data engineering,
less-common language toolchains, printing and Bluetooth, and virtualization.

Each row records `nl`, `bash`, `category`, `risk`, `family`, provenance, shard,
and a content-derived ID. The merger rejects normalized duplicates, commands
or prompts already present in NL2SH-ALFA train/test, comment-only command
variants, and overrepresented categories/command heads.

The first corpus is reproducible from three independently authored shards:

```powershell
python .\tools\build_manual_synth_cloud_infra.py
python .\tools\build_manual_synth_dev_data.py
python .\tools\build_manual_security_shell.py
python .\tools\merge_manual_corpus.py `
  .\data\manual_synth_cloud_infra.json `
  .\data\manual_synth_dev_data.json `
  .\data\manual_synth_security_shell.json
```

Build the second corpus and require it to remain distinct from the first:

```powershell
python .\tools\build_manual_synth_extended.py
python .\tools\merge_manual_corpus.py `
  .\data\manual_synth_extended.json `
  --exclude-corpus .\data\nl2sh-manual-gap-10000.json `
  --output .\data\nl2sh-manual-gap-second-10000.json `
  --summary .\data\nl2sh-manual-gap-second-10000-summary.json `
  --minimum 10000
```

Combine the two audited corpora while retaining the diversity caps:

```powershell
python .\tools\merge_manual_corpus.py `
  .\data\nl2sh-manual-gap-10000.json `
  .\data\nl2sh-manual-gap-second-10000.json `
  --output .\data\nl2sh-manual-gap-25000.json `
  --summary .\data\nl2sh-manual-gap-25000-summary.json `
  --minimum 25000
```

Local build:

```powershell
python .\generate_high_quality_dataset.py
```

`generate_superset.py` remains as a compatibility alias for the same full
build:

```powershell
python .\generate_superset.py
```

To exclude higher-risk examples, pass `--max-risk safe` or
`--max-risk caution`. To make a deterministic, family-aware development
subset, pass `--manual-limit N`.

Validate corpus structure, uniqueness, and split isolation after a build:

```powershell
python .\tools\validate_augmented_dataset.py
```

The current full build has 59,743 train rows, 6,705 validation rows, and the
300-row official test split. Publishing remains explicit:

Publish the completed `DatasetDict` after building it:

```powershell
python .\generate_high_quality_dataset.py `
  --push-to-hub `
  --hub-repo YOUR_HF_USERNAME/nl2sh-alfa-synth `
  --private
```

Authentication is read from `HF_TOKEN` in the process environment, then from
the local `.env` file if present, then from the Hugging Face CLI login cache.
Omit `--private` to create a public dataset. Hub publication is opt-in so a
local regeneration cannot accidentally overwrite a remote dataset.

## 3. Run training interactively

Fine-tuned FLAN-T5-small:

```powershell
python .\train_flan_t5.py --epochs 3 --batch-size 16
```

Resume its most recent Trainer checkpoint:

```powershell
python .\train_flan_t5.py --resume-from-checkpoint
```

Transfer-initialized custom seq2seq:

```powershell
python .\train_seq2seq.py `
  --variant seq2seq-transfer `
  --epochs 3 `
  --batch-size 32
```

Scratch baseline:

```powershell
python .\train_seq2seq.py `
  --variant seq2seq-scratch `
  --epochs 3 `
  --batch-size 32
```

Train both LSTM variants sequentially:

```powershell
python .\train_lstm_seq2seq.py `
  --variant both `
  --epochs 3 `
  --batch-size 16
```

Use `--variant scratch` or `--variant transfer` to run only one. LSTM
checkpoints are stored separately under `checkpoints/lstm-seq2seq-scratch` and
`checkpoints/lstm-seq2seq-transfer`.

Both trainers print live loss updates. FLAN-T5 saves Trainer checkpoints by
epoch; the custom trainer saves every epoch plus `best_model.pt` selected by
validation loss. If CUDA runs out of memory, halve `--batch-size`; for FLAN-T5,
increase `--gradient-accumulation-steps` to preserve the effective batch size.

## 4. Evaluate

After regenerating the dataset and training at least one model:

```powershell
python .\evaluate_models.py
```

Evaluation automatically discovers every custom model run (preferring its
validation-selected `best_model.pt`) and every completed Hugging Face
encoder-decoder model under `checkpoints/`. Intermediate Trainer
`checkpoint-*` directories and unrelated causal models are ignored. It uses
the complete official test split, accepts either official Bash reference, and
writes a formatted terminal table plus `data/benchmark_results.json` and
`data/benchmark_results.csv`.

For a quick pipeline check:

```powershell
python .\evaluate_models.py --max-eval 10
```
