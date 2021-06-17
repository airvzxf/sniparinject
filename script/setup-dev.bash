#!/usr/bin/env bash
set -ev

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

source ../venv/bin/activate
cd ../
rm -fR venv
python3 -m venv venv
pip install --upgrade setuptools pip
pip install -r ../requirements.txt
pip install -e .
deactivate
