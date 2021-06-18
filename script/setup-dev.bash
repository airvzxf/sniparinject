#!/usr/bin/env bash
set -ev

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

cd ../src || exit
rm -fR venv
python3 -m venv ../venv
source ../venv/bin/activate
pip install --upgrade setuptools pip
pip install -r ../requirements.txt
pip install -e .
deactivate
