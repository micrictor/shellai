# Shellai

Shellai (pronounced “shellay”) turns a natural-language request into an editable shell command,
entirely on the local machine. Version 0.2 is a native Rust rewrite: Python, PyTorch, Transformers,
Frida, process injection, and the `ptrace_scope` change are no longer part of the runtime.

The default model is
[`LiquidAI/LFM2.5-1.2B-Instruct-GGUF`](https://huggingface.co/LiquidAI/LFM2.5-1.2B-Instruct-GGUF),
using its Quantization-Aware Distillation Q4_0 checkpoint.

## How it works

- One `shellai` executable contains the client and server.
- `llama.cpp`/`libllama` is compiled and linked into the executable through `llama-cpp-2`; users do
  not need Ollama or a separately installed inference server.
- The client talks to a per-user Unix domain socket on Linux/macOS or a named pipe on Windows.
- If no server is listening, the client starts one and retries the request automatically.
- The GGUF is loaded only for inference. After 60 seconds without an inference request, the server
  drops the model and returns its memory to the operating system. The lightweight server remains
  ready for the next request.
- The model is downloaded once into the normal Hugging Face cache, or a local GGUF can be selected.

## Install

Release archives contain the native executable and `shellai.plugin.zsh`.

1. Put `shellai` (or `shellai.exe`) on `PATH`.
2. Ensure Hugging Face is reachable. If authentication is required in your environment, use
   either `hf auth login` or an `HF_TOKEN` environment variable.
3. Source the plugin from `.zshrc`:

   ```zsh
   source /path/to/shellai.plugin.zsh
   ```

4. Optionally pre-download the default quant:

   ```console
   shellai download
   ```

The first request can also perform the download automatically. Windows builds use a native named
pipe; the zsh integration can be sourced from a Windows zsh environment such as MSYS2.

## Use from zsh

Type the existing trigger and press Enter:

```console
ai, show the ten largest files in this directory
```

The request is replaced in the current ZLE buffer by the generated command. It is never executed
automatically—review or edit it, then press Enter again.

Press `Alt-A` to open a separate minibuffer, similar to manai. The command already in the main
buffer is sent as context, and the answer replaces it. Change the binding before sourcing the
plugin if desired:

```zsh
export SHELLAI_HOTKEY='^G'
source /path/to/shellai.plugin.zsh
```

The minibuffer has its own persistent history: use the normal ZLE bindings such as Up/Down and
`Ctrl-R` to recall or search earlier shellai requests without adding them to ordinary command
history. It keeps 1,000 entries by default in
`${XDG_STATE_HOME:-$HOME/.local/state}/shellai/history`. Both are configurable before sourcing the
plugin:

```zsh
export SHELLAI_HISTORY_FILE="$HOME/.shellai_history"
export SHELLAI_HISTORY_SIZE=2000
```

The native client is also usable directly:

```console
shellai ask -- "find files modified in the last 24 hours"
shellai ask --context "git log" -- "only show commits from this week"
```

Zero-shot inference is the default. It constrains the model response with an internal command
envelope, stops generation at the closing marker, validates the complete envelope, and prints only
the command within it. The envelope is never included in the command inserted into ZLE.

### Guided workflow experiment

The proposed help-grounded workflow is available explicitly:

```console
shellai ask --workflow guided -- "list every file in /etc containing root"
```

It performs up to four phases: asks the model for a manual-description expression, safely
normalizes it and runs `man -k` (`Get-Help -Name` on Windows), asks the model to select one or two
names that actually appeared in the results, then supplies the complete selected man/help pages
for final generation. Invalid or empty discovery searches and invalid selections are retried up to
three times. Local help processes have a 15-second timeout. Model text is treated as data and is
never evaluated as a general shell command during this workflow.

This mode is experimental and is not the default. Current evaluations found that the models often
solve the request directly instead of following the discovery or selection instruction. Use
`--workflow zero-shot` (the default) for normal command generation.

The QAD checkpoint and Liquid AI sampling values are the defaults. An alternate GGUF can still be
evaluated without changing the config:

```console
SHELLAI_MODEL=/models/LFM2.5-1.2B-Instruct-Q8_0.gguf \
SHELLAI_TOP_K=50 SHELLAI_TEMPERATURE=0.1 SHELLAI_REPEAT_PENALTY=1.05 \
shellai ask --workflow zero-shot -- "list every file in /etc containing root"
```

## Configuration

Create a default config and print its path:

```console
shellai config --init
```

Linux normally uses `~/.config/shellai/config.toml`; platform conventions are used on macOS and
Windows. Available values are:

```toml
# Set this to bypass Hugging Face entirely.
# model_path = "/models/LFM2.5-1.2B-Instruct-QAD-Q4_0.gguf"

repository = "LiquidAI/LFM2.5-1.2B-Instruct-GGUF"
model_file = "LFM2.5-1.2B-Instruct-QAD-Q4_0.gguf"
model_ttl_seconds = 60
context_size = 32768
max_new_tokens = 256
# threads = 8
gpu_layers = 999
top_k = 50
top_p = 0.95
temperature = 0.1
repeat_penalty = 1.05
# seed = 42  # Uncomment for reproducible output.
```

An existing config remains authoritative and is not rewritten during upgrades. To adopt the new
LFM2.5 QAD default, update its `repository` and `model_file` values as shown above (and remove an
old `model_path` override), or move the config aside and run `shellai config --init` again.

The sampling defaults use Liquid AI's recommended `top_k = 50`, `temperature = 0.1`, and
`repeat_penalty = 1.05`; `top_p` remains `0.95`. Exact commands can still vary between requests.
Set `seed` when deterministic output is more important than fresh sampling.

`SHELLAI_MODEL` overrides `model_path`, and `SHELLAI_MODEL_TTL` overrides the TTL. Sampler values
can be overridden for model evaluation with `SHELLAI_TOP_K`, `SHELLAI_TEMPERATURE`, and
`SHELLAI_REPEAT_PENALTY`. Model and sampler settings are sent with each inference request, so they
take effect even when the server is already running. If the requested model differs from the one
in memory, the server unloads it and loads the requested model. A TTL of `0` unloads immediately
after each request. The TTL is a server lifecycle setting, so restart the server after changing it:

```console
shellai stop
```

Useful lifecycle commands:

```console
shellai status
shellai server --model-ttl 300   # foreground/debug mode
shellai stop
shellai plugin                   # print the bundled plugin
```

## Metrics

Every inference appends a server-side JSONL record containing its workflow/stage IDs, prompt and
completion token counts, total context use, configured context limit, inference duration, and RSS
before/after/peak. Every client workflow appends a separate aggregate record with total token use,
summed server inference time, peak server RSS, local discovery/help time, success, and end-to-end
latency. Prompts, generated commands, search output, and help-page contents are not logged.

Print the platform-specific paths with:

```console
shellai metrics
```

The files are normally `~/.cache/shellai/metrics/server.jsonl` and `client.jsonl` on Linux. A
32K context is the configured ceiling; each inference allocates a smaller 512-token-aligned active
context when its prompt does not need the full window.

## Build

Requirements are Rust 1.89 or newer, CMake, Clang/libclang, a C/C++ compiler, and Git. The Rust
build compiles the bundled `llama.cpp` sources and statically links its libraries.

```console
cargo build --release
cargo test --locked
```

Apple Silicon enables the Metal backend automatically; it can also be requested explicitly with
`cargo build --release --features metal`. Optional CUDA and Vulkan builds use the corresponding
Cargo features and require their platform SDKs.

Continuous integration compiles the release targets requested by the project:

- `x86_64-unknown-linux-gnu` (Linux x64)
- `x86_64-pc-windows-msvc` (Windows x64)
- `aarch64-apple-darwin` (macOS Apple Silicon/Metal)

## Protocol and safety

IPC messages are bounded (8 MiB), newline-delimited JSON. Unix sockets live inside a mode-0700 per-user
cache directory. Generated text is inserted into the editable command line and is not run by
Shellai. As with any generated command, inspect it before execution.

Shellai is MIT licensed. The downloaded model remains subject to the Gemma license.
