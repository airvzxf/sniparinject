#!/usr/bin/env bash
set -ev

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

cd ../
rm -fR build dist src/*.egg-info
./venv/bin/python3 -m pip install --upgrade pip build
./venv/bin/python3 -m build
./venv/bin/python3 -m twine upload --repository sniparinject dist/*
