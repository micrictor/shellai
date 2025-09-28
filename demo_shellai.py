from src.shellai.shellai import ShellAI

m = ShellAI()
m.load_model()


for prompt in [
    "what are the files bigger than 1mb in the current directory",
    "find files modified in the last 24 hours",
    "compress all .txt files into an archive",
    "show me the total disk usage of my home directory",
    "search for \"EGG\" in all ELF files in /usr/bin",
]: 
    print(f"Prompt: {prompt}")
    print(f"Generated command: {m.generate_command(prompt)}")
