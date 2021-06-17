#!/usr/bin/env bash
set -e

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

cd ../src || exit

source ../venv/bin/activate
find ./ \
  -type f \
  -name "*.py" \
  -not -path "./build/*" \
  -exec pylint '{}' +
deactivate
