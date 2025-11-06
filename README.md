## Shellai

Shellai (pronounced shellay) is a command-line interface for getting AI assistance without network calls or a separate interface.
It's built around the idea that I should be able to, in my terminal, simply type `ai, do this thing` and have it generate the command for me.

Shellai uses local small-language models (SLMs) to fulfill user requests. Your data stays on your machine. Unlike other tools like `shellgpt`, the local inference is built into this tool - no need to turn up an ollama server seperatly.

## Install steps

1. `git clone https://github.com/micrictor/shellai.git && cd shellai && pip install -e .` 
1.  `ptrace` must be allowed for all processes owned by the same user. This can be set temporarily (until next reboot) using `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`.
    *   Setting this can be bad, since it allows any process running as a user to access memory/internal state of all other processes for that user.
2.  `hf login` to set up your HuggingFace credentials for use to download the model.
3.  In HuggingFace, accept the [Gemma license](https://huggingface.co/google/gemma-3-270m-it) and request access to [my finetuned model, which is the default for the tool](https://huggingface.co/micrictor/gemma-3-270m-it-ft-bash). This is optional if you want to use other models.
4.  Run your first prompt, like `ai, show me the last 10 lines of the readme`

## Model tests

Looking for some variant on "grep all the files for 'root'"

### Untrained

```bash
(.venv) [mtu@archlap shellai]$ time ai, --model google/gemma-3-270m-it list every file in /etc that contains the string "root"
Using model google/gemma-3-270m-it
🐢🐢🐢🐢🐢🐢🐢🐢
real	0m11.176s
user	0m12.742s
sys	0m1.086s
(.venv) [mtu@archlap shellai]$ ls -l /etc^C
(.venv) [mtu@archlap shellai]$ time ai, --model google/gemma-3-270m-it list every file in /etc that contains the string "root"
Using model google/gemma-3-270m-it
🐢🐢🐢
real	0m5.206s
user	0m12.841s
sys	0m1.010s
(.venv) [mtu@archlap shellai]$ ls /etc/passwd
```

### Trained

```bash
(.venv) [mtu@archlap shellai]$ time ai, list every file in /etc that contains the string "root"
Using model micrictor/gemma-3-270m-it-ft-bash
🐢🐢🐢🐢🐢🐢🐢🐢
real	0m10.549s
user	0m19.052s
sys	0m1.059s
(.venv) [mtu@archlap shellai]$ find /etc -type f -exec grep -l root '{}' \;
```


