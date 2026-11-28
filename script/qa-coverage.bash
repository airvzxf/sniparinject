#!/usr/bin/env bash
set -e

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

cd ../test || exit

source ../venv/bin/activate
coverage run 1>/dev/null
coverage report
coverage html 1>/dev/null
deactivate
