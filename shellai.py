#!/usr/bin/env python3
"""
Shellai - AI-powered shell command generation

A command-line tool that uses a local ByT5 model to convert natural language
descriptions into shell commands.
"""

import argparse
import os
import sys
import re
import warnings


"""
https://huggingface.co/blog/gemma-peft
"""

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore")
os.environ['TRANSFORMERS_VERBOSITY'] = 'critical'
EXTRACTION_REGEX = re.compile(r'```bash(.*?)```', re.DOTALL | re.IGNORECASE | re.MULTILINE)

import torch
from transformers import pipeline

class ShellAI:
    """Main class for the ShellAI tool."""
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = "cpu"  # Use CPU for compatibility
        
    def load_model(self):
        """Load the ByT5 model and tokenizer from HuggingFace."""
        model_name = "google/gemma-3-270m-it"
        
        try:
           self.pipe = pipeline(
                "text2text-generation",
                model=model_name,
                device=0 if torch.cuda.is_available() else "cpu",
                torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
            )
            
            
        except Exception as e:
            print(f"Error loading model: {e}", file=sys.stderr)
            sys.exit(1)
    
    def generate_command(self, prompt: str) -> str:
        """Generate a shell command from the given prompt."""

        if self.pipe is None:
            raise ValueError("Model not loaded. Call load_model() first.")
        prompt = f"""You MUST provide the MOST CORRECT AND SYNTACTICALLY VALID bash command to accomplish a task.
The MOST CORRECT bash command to accomplish the task "{prompt}" is
```bash
"""
        output = self.pipe(
            prompt,
            max_new_tokens=200
        )
        
        generated_command = output[0]["generated_text"]
        print(f"DEBUG: Full generated output:\n{generated_command}", file=sys.stderr)
        # Extract the command from the output
        matches = EXTRACTION_REGEX.search(generated_command)
        if matches:
            return matches.group(1).strip()

        return generated_command.strip()


def main():
    """Main entry point for the shellai tool."""
    parser = argparse.ArgumentParser(
        description="AI-powered shell command generation",
        prog="shellai",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  shellai list all files in current directory
  shellai find files modified in the last 24 hours
  shellai compress all .txt files into an archive
        """
    )
    
    parser.add_argument(
        "prompt",
        nargs="*",
        help="Natural language description of the desired shell command"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="shellaipad_token_id 0.1.0"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Join all arguments to form the prompt
    if not args.prompt:
        parser.print_help()
        sys.exit(1)
    
    prompt = " ".join(args.prompt)
    
    if args.verbose:
        print(f"Input prompt: {prompt}", file=sys.stderr)
    
    # Initialize and run the AI
    ai = ShellAI()
    ai.load_model()
    
    try:
        command = ai.generate_command(prompt)
        # Output the generated command to stdout
        print(command)
        
    except Exception as e:
        print(f"Error generating command: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
