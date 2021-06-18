#!/usr/bin/env bash
set -ev

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

cd ../src || exit
rm -fR build dist ./*.egg-info
source ../venv/bin/activate
python3 -m pip install --upgrade pip build twine
python3 -m build
deactivate
