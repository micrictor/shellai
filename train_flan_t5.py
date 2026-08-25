import argparse
from pathlib import Path

import torch
from datasets import load_from_disk
from transformers import (
    AutoModelForSeq2SeqLM,
    AutoTokenizer,
    DataCollatorForSeq2Seq,
    Seq2SeqTrainer,
    Seq2SeqTrainingArguments,
)


def train_flan_t5(
    dataset_dir,
    model_id="google/flan-t5-small",
    output_dir="checkpoints/flan-t5-small-ft-bash",
    epochs=3,
    batch_size=16,
    gradient_accumulation_steps=4,
    learning_rate=1e-4,
    max_source_length=128,
    max_target_length=128,
    logging_steps=25,
    seed=42,
    resume_from_checkpoint=None,
    gradient_checkpointing=False,
):
    dataset = load_from_disk(str(dataset_dir))
    if "validation" not in dataset:
        if "test" not in dataset:
            raise ValueError("Dataset needs a validation split (or legacy test split).")
        print(
            "WARNING: legacy dataset has no validation split; using test for "
            "validation. Regenerate the dataset before reporting final metrics."
        )
        validation_split = dataset["test"]
    else:
        validation_split = dataset["validation"]

    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_id)
    prefix = "translate natural language to bash: "

    def preprocess_function(examples):
        model_inputs = tokenizer(
            [prefix + text for text in examples["nl"]],
            max_length=max_source_length,
            truncation=True,
        )
        labels = tokenizer(
            text_target=examples["bash"],
            max_length=max_target_length,
            truncation=True,
        )
        model_inputs["labels"] = labels["input_ids"]
        return model_inputs

    tokenized_train = dataset["train"].map(
        preprocess_function,
        batched=True,
        remove_columns=dataset["train"].column_names,
        desc="Tokenizing training split",
    )
    tokenized_validation = validation_split.map(
        preprocess_function,
        batched=True,
        remove_columns=validation_split.column_names,
        desc="Tokenizing validation split",
    )

    use_bf16 = (
        torch.cuda.is_available() and torch.cuda.get_device_capability()[0] >= 8
    )
    use_fp16 = torch.cuda.is_available() and not use_bf16
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    effective_batch_size = batch_size * gradient_accumulation_steps
    print(
        f"Fine-tuning {model_id} | train={len(tokenized_train):,} | "
        f"validation={len(tokenized_validation):,} | "
        f"effective_batch_size={effective_batch_size}"
    )
    print(f"Checkpoints and Trainer state: {output_dir.resolve()}")

    training_args = Seq2SeqTrainingArguments(
        output_dir=str(output_dir),
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_strategy="steps",
        logging_steps=logging_steps,
        learning_rate=learning_rate,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        weight_decay=0.01,
        warmup_ratio=0.05,
        lr_scheduler_type="linear",
        save_total_limit=2,
        num_train_epochs=epochs,
        predict_with_generate=False,
        fp16=use_fp16,
        bf16=use_bf16,
        gradient_checkpointing=gradient_checkpointing,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        report_to="none",
        seed=seed,
        data_seed=seed,
    )
    trainer = Seq2SeqTrainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_train,
        eval_dataset=tokenized_validation,
        processing_class=tokenizer,
        data_collator=DataCollatorForSeq2Seq(tokenizer, model=model),
    )
    train_result = trainer.train(resume_from_checkpoint=resume_from_checkpoint)
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))
    trainer.save_state()
    trainer.log_metrics("train", train_result.metrics)
    trainer.save_metrics("train", train_result.metrics)
    validation_metrics = trainer.evaluate(metric_key_prefix="validation")
    trainer.log_metrics("validation", validation_metrics)
    trainer.save_metrics("validation", validation_metrics)
    print(f"Saved best fine-tuned model to '{output_dir.resolve()}'")
    return output_dir


def parse_args():
    parser = argparse.ArgumentParser(description="Fine-tune FLAN-T5 for NL-to-Bash.")
    parser.add_argument("--dataset-dir", default="data/nl2sh-alfa-synth")
    parser.add_argument("--model-id", default="google/flan-t5-small")
    parser.add_argument("--output-dir", default="checkpoints/flan-t5-small-ft-bash")
    parser.add_argument("--epochs", type=float, default=3)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=4)
    parser.add_argument("--learning-rate", type=float, default=1e-4)
    parser.add_argument("--max-source-length", type=int, default=128)
    parser.add_argument("--max-target-length", type=int, default=128)
    parser.add_argument("--logging-steps", type=int, default=25)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--resume-from-checkpoint",
        nargs="?",
        const=True,
        default=None,
        help="Resume from the latest checkpoint, or pass a checkpoint path.",
    )
    parser.add_argument("--gradient-checkpointing", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    train_flan_t5(
        dataset_dir=args.dataset_dir,
        model_id=args.model_id,
        output_dir=args.output_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        learning_rate=args.learning_rate,
        max_source_length=args.max_source_length,
        max_target_length=args.max_target_length,
        logging_steps=args.logging_steps,
        seed=args.seed,
        resume_from_checkpoint=args.resume_from_checkpoint,
        gradient_checkpointing=args.gradient_checkpointing,
    )
