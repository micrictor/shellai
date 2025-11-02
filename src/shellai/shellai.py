#!/usr/bin/env python3
"""
Shellai - AI-powered shell command generation

A command-line tool that uses a local ByT5 model to convert natural language
descriptions into shell commands.
"""

import argparse
import multiprocessing
import os
import subprocess
import sys
import threading
import re
import warnings

from shellai.tty import GenericTTYWriter

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore")
os.environ['TRANSFORMERS_VERBOSITY'] = 'critical'
os.environ["TOKENIZERS_PARALLELISM"] = "true" 
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
        model_name = "micrictor/gemma-3-270m-it-ft-bash"
        
        try:
           self.pipe = pipeline(
                "text-generation",
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
        messages = [
            {"role": "system", "content": "You are a helpful assistant that translates natural language to bash commands."},
            {"role": "user", "content": f"Generate single Bash command: {prompt}"}
        ]
        output = self.pipe(
            messages,
            max_new_tokens=256,
            disable_compile=True,
            clean_up_tokenization_spaces=False,
            return_full_text=False,
        )[0]
        
        generated_command = output["generated_text"]
        # Extract the command from the output
        matches = EXTRACTION_REGEX.search(generated_command)
        if matches:
            return matches.group(1).strip()

        return generated_command.strip().replace('“','"').replace('”','"')

def command_exists(command_string: str) -> bool:
    """Check if a command exists in the system PATH."""
    command = command_string.split()[0]
    is_on_path = any(
        os.access(os.path.join(path, command), os.X_OK)
        for path in os.environ["PATH"].split(os.pathsep)
    )
    if is_on_path:
        return True
    # Check for built-ins/functions
    cmd = subprocess.run(["bash", "-c", f"type {command}"], capture_output=True, text=True)
    return cmd.returncode == 0

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
    # Start a background thread to print a turtle emoji every second while the model loads
    stop_event = threading.Event()
    def print_turtle():
        import time
        turt_count = 1
        while not stop_event.is_set():
            print(("🐢" * turt_count) + "\r", end="", flush=True)
            turt_count += 1
            time.sleep(1)
        print("\r", end='', flush=True)
    t = threading.Thread(target=print_turtle)
    t.start()
    ai.load_model()

    try:
        with GenericTTYWriter() as tty_writer:
            command = ai.generate_command(prompt)
            command = "whoaasdasdmi"
            while command is None or command == "" or not tty_writer.check_command(command):
                command = ai.generate_command(prompt)

            multiprocessing.set_start_method('spawn')
            p = multiprocessing.Process(target=child_process, args=(tty_writer, command))
            p.start()
            stop_event.set()
            t.join()
            os._exit(0)

    except Exception as e:
        print(f"Error generating command: {e.with_traceback()}", file=sys.stderr)
        sys.exit(1)

def child_process(tty_writer, command):
    tty_writer.static_write_to_tty(tty_writer.parent_shell_pid, command)

if __name__ == "__main__":
    main()
