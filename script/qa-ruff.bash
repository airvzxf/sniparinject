#!/usr/bin/env bash
set -e

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

cd .. || exit

source ./venv/bin/activate
ruff check src test
deactivate
