---
name: fixture-secure-review
description: INERT TEST DATA. Defensive review guidance.
---
# Review guide
Avoid eval() and os.system on untrusted input.
Review shell argument quoting and use an argument vector.
Keep credentials out of logs. Check that destinations use HTTPS.
