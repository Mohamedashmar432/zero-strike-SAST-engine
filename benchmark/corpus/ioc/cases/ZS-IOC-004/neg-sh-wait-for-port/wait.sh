#!/bin/sh
until echo > /dev/tcp/$HOST/$PORT; do sleep 1; done
