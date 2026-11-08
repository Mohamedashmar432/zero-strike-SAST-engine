#!/bin/sh
exec 3<>/dev/tcp/localhost/5432 && echo ok
