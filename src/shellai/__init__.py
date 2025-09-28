"""
Shellai - AI-powered shell command generation

A command-line tool that uses a local model to convert natural language
descriptions into shell commands.
"""

__version__ = "0.1.0"
__author__ = "micrictor"

from .shellai import ShellAI, main

__all__ = ["ShellAI", "main"]