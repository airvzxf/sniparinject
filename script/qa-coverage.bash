#!/usr/bin/env bash
set -e

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

cd ../test || exit

source ../venv/bin/activate
coverage3 run 1>/dev/null
coverage3 report
coverage3 html 1>/dev/null
deactivate
