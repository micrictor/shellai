## Shellai

Shellai (pronounced shellay) is a command-line interface for getting AI assistance without network calls or a separate interface.
It's built around the idea that I should be able to, in my terminal, simply type `ai, do this thing` and have it generate the command for me.

The name is inspired by a turtle I tripped over on a run on 21 September 2025. That morning, my house had a power outage, so I couldn't get AI assistance to try some file combinations for a firmware analysis I was doing.

I called it "Shellay" (think: Forrest Gump), which free-flow associated to shell AI, and from there to how existing tools like Goose and Gemini CLI were often overkill and certainly not resilient.

Shellai uses local small-language models (SLMs) by default. Your data stays on your machine. Unlike other tools like `shellgpt`, the local inference is built into this tool - no need to turn up an ollama server seperatly.

TODO:

* print turtles while operating, write command to tty
* run daemon with model pre-loaded in memory. Should save like 80% of runtime
* train "hackerai" with https://github.com/CoolHandSquid/TireFire/blob/TireFire_V4/WeeklyUpdateFiles/23-04-13_21%3A09%3A32.csv