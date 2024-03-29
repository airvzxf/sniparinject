#!/usr/bin/env bash
set -e

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

cd ../test || exit

source ../venv/bin/activate
pytest
deactivate
