# Shellai

Shellai (pronounced “shellay”) turns a natural-language request into an editable shell command,
entirely on the local machine. Version 0.2 is a native Rust rewrite: Python, PyTorch, Transformers,
Frida, process injection, and the `ptrace_scope` change are no longer part of the runtime.

The default model is
[`micrictor/gemma-3-270m-it-ft-bash-GGUF`](https://huggingface.co/micrictor/gemma-3-270m-it-ft-bash-GGUF),
using its Q8_0 quantization.

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
2. Accept the Gemma license on the model page and authenticate with either `hf auth login` or an
   `HF_TOKEN` environment variable.
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

The native client is also usable directly:

```console
shellai ask -- "find files modified in the last 24 hours"
shellai ask --context "git log" -- "only show commits from this week"
```

### Guided workflow experiment

The proposed help-grounded workflow is available explicitly:

```console
shellai ask --workflow guided -- "list every file in /etc containing root"
```

It performs up to four phases: asks the model for a `man -k` search (`Get-Help -Name` on
Windows), executes that constrained search without a shell, asks the model to select one or two
names that actually appeared in the results, then supplies the complete selected man/help pages
for final generation. Invalid or empty discovery searches and invalid selections are retried up to
three times. Local help processes have a 15-second timeout. Model text is never evaluated as a
general shell command during this workflow.

This mode is experimental and is not the default. Evaluation with the current command-specialized
270M fine-tune found that it often solves the request directly instead of following the discovery
or selection instruction. Use `--workflow zero-shot` (the default) for its trained behavior and
compare the metric logs when iterating on a more instruction-capable model.

## Configuration

Create a default config and print its path:

```console
shellai config --init
```

Linux normally uses `~/.config/shellai/config.toml`; platform conventions are used on macOS and
Windows. Available values are:

```toml
# Set this to bypass Hugging Face entirely.
# model_path = "/models/gemma-3-270m-it-ft-bash-Q8_0.gguf"

repository = "micrictor/gemma-3-270m-it-ft-bash-GGUF"
model_file = "gemma-3-270m-it-ft-bash-Q8_0.gguf"
model_ttl_seconds = 60
context_size = 32768
max_new_tokens = 256
# threads = 8
gpu_layers = 999
top_k = 64
top_p = 0.95
# seed = 42  # Uncomment for reproducible output.
```

The sampling defaults mirror the fine-tuned model's Transformers `generation_config.json`:
`do_sample = true`, `top_k = 64`, and `top_p = 0.95`. Consequently, exact commands can vary
between requests. Set `seed` when deterministic output is more important than fresh sampling.

`SHELLAI_MODEL` overrides `model_path`, and `SHELLAI_MODEL_TTL` overrides the TTL. A TTL of `0`
unloads immediately after each request. Restart the server after changing configuration:

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
