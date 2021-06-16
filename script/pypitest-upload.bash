#!/usr/bin/env bash
set -ev

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

cd ../
rm -fR build dist src/*.egg-info
./venv/bin/python3 -m pip install --upgrade pip build
./venv/bin/python3 -m build
./venv/bin/python3 -m twine upload --repository test-sniparinject dist/*
#python3 -m pip install --index-url https://test.pypi.org/simple/ --no-deps sniparinject==0.0.0.dev4
#python3 -m pip install --index-url https://test.pypi.org/simple/ sniparinject==0.0.0.dev4
