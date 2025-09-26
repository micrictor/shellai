## Shellai

Shellai (pronounced shellay) is a command-line interface for getting AI assistance without network calls or a separate interface.
It's built around the idea that I should be able to, in my terminal, simply type `ai, do this thing` and have it generate the command for me.

It uses local small-language models (SLMs) by default, so your data stays on your machine. Unlike other tools like `shellgpt`, the local inference is built into this tool - no need to turn up an ollama server seperatly.

TODO:

* print turtles while operating, write command to tty
* run daemon with model pre-loaded in memory. Should save like 80% of runtime
* train "hackerai" with https://github.com/CoolHandSquid/TireFire/blob/TireFire_V4/WeeklyUpdateFiles/23-04-13_21%3A09%3A32.csv