#!/bin/sh
socat TCP-LISTEN:8080,fork TCP:backend:80
