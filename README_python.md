# Shellai Python Proof of Concept

A Python implementation of the Shellai tool using the ByT5 model from HuggingFace.

## Overview

This proof of concept implements the core functionality described in the main README using:
- **Python 3.12** as the runtime
- **argparse** for command-line argument parsing (Python equivalent of Rust's clap)
- **PyTorch + Transformers** for model inference (Python equivalent of tch-rs)
- **kevinum/byt5-small-finetuned-English-to-BASH** model from HuggingFace

## Installation

1. Ensure Python 3.12+ is installed
2. Create and activate the virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Linux/Mac
   # or .venv\Scripts\activate  # On Windows
   ```
3. Install dependencies:
   ```bash
   pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
   pip install transformers huggingface_hub protobuf
   ```

## Usage

### Direct Python Script
```bash
python shellai.py "list all files in current directory"
python shellai.py "find files modified in the last 24 hours"
python shellai.py "show disk usage"
```

### Using the Wrapper Script
```bash
./ai "list all files in current directory"
./ai "find files modified in the last 24 hours"  
./ai "show disk usage"
```

### Command Line Options
```bash
python shellai.py --help          # Show help
python shellai.py --version       # Show version
python shellai.py --verbose "cmd" # Enable verbose output
```

## Examples

```bash
# Basic file operations
./ai "list all files in current directory"
# Output: ls

./ai "remove all txt files"
# Output: rm txt

./ai "show disk usage"
# Output: df

./ai "count lines in all python files"
# Output: python | wc -l
```

## Architecture

- **ShellAI class**: Main class that handles model loading and inference
- **load_model()**: Downloads and loads the ByT5 model from HuggingFace
- **generate_command()**: Takes natural language input and generates bash commands
- **main()**: Handles command-line parsing and orchestrates the workflow

## Model Details

- **Model**: `kevinum/byt5-small-finetuned-English-to-BASH`
- **Type**: ByT5 (Byte-level T5) - character-level sequence-to-sequence model
- **Input**: Natural language descriptions
- **Output**: Bash commands
- **Device**: CPU (for compatibility)

## Files

- `shellai.py` - Main Python implementation
- `ai` - Bash wrapper script for easier usage
- `README_python.md` - This documentation

## Notes

- The model is downloaded on first use and cached locally
- CPU-only PyTorch is used for maximum compatibility
- All output goes to stdout, errors/progress to stderr
- The model generates commands but does not execute them (for safety)

## Future Improvements

- Add model caching to avoid reloading on each call
- Support for GPU acceleration when available
- Better error handling and validation
- Integration with shell history
- Support for additional model formats
