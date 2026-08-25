import argparse

from train_seq2seq import train_model


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Train attention LSTM seq2seq scratch and/or FLAN-T5 "
            "embedding-transfer variants."
        )
    )
    parser.add_argument(
        "--variant",
        choices=["both", "scratch", "transfer"],
        default="both",
    )
    parser.add_argument("--dataset-dir", default="data/nl2sh-alfa-synth")
    parser.add_argument("--tokenizer-name", default="google/flan-t5-small")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--embed-dim", type=int, default=256)
    parser.add_argument("--hidden-dim", type=int, default=256)
    parser.add_argument("--max-source-length", type=int, default=96)
    parser.add_argument("--max-target-length", type=int, default=64)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--log-steps", type=int, default=100)
    parser.add_argument(
        "--freeze-transfer-embeddings",
        action="store_true",
        help="Keep the transferred FLAN-T5 embedding matrix fixed.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Initialize each selected model without training or saving.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    variants = (
        ["scratch", "transfer"]
        if args.variant == "both"
        else [args.variant]
    )
    for variant in variants:
        train_model(
            model_variant=f"seq2seq-{variant}",
            architecture="lstm",
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
            freeze_embeddings=(
                args.freeze_transfer_embeddings and variant == "transfer"
            ),
            dry_run=args.dry_run,
        )


if __name__ == "__main__":
    main()
