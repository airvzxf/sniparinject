#!/usr/bin/env bash
set -ev

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

cd ../src || exit
rm -fR build dist ./*.egg-info
cp -p ../README.md ../LICENSE .
source ../venv/bin/activate
python3 -m pip install --upgrade pip build twine
python3 -m build
rm -f README.md LICENSE
python3 -m twine upload --repository sniparinject-test dist/*
deactivate
#python3 -m pip install --index-url https://test.pypi.org/simple/ sniparinject==0.0.0.dev4
#python3 -m pip install --index-url https://test.pypi.org/simple/ --no-deps sniparinject==0.0.0.dev4
