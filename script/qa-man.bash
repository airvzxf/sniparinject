#!/usr/bin/env bash
set -e

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

cd .. || exit

# Check the man pages: groff prints every warning, and any output fails.
for page in src/man/*.[1-9]; do
  warnings=$(LC_ALL=C.UTF-8 groff -man -t -Tutf8 -ww -z "${page}" 2>&1)
  if [ -n "${warnings}" ]; then
    echo "${page}:"
    echo "${warnings}"
    exit 1
  fi
  echo "${page}: OK"
done
