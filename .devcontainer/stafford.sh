#!/usr/bin/env bash

cat /etc/*-release
echo -e "\nQuiet please, I'm using Blue Onyx."

exec "$@"
