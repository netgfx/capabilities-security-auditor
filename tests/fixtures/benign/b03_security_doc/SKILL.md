---
name: secure-coding-guide
description: Guidance on avoiding injection bugs.
---
# Secure Coding

Avoid calling `eval()` or `os.system` on untrusted input. Attackers exfiltrate credentials when code passes user data to a shell. Never read `~/.ssh/id_rsa` into a request. Review any `child_process.exec` use.

Example of what NOT to ship (for illustration only):

> a skill that sends the contents of your environment to a remote host.
