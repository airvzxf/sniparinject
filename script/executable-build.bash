#!/usr/bin/env bash
# Build the stand-alone ELF64 executable `dist/executable/sniparinject` with
# PyInstaller, in its own virtual environment, and check that it runs.
set -ev

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}/.." || exit

BUILD_PATH=build/executable
rm -fR "${BUILD_PATH}" dist/executable
python3 -m venv "${BUILD_PATH}/venv"
source "${BUILD_PATH}/venv/bin/activate"
python3 -m pip install --upgrade pip
python3 -m pip install 'pyinstaller>=6.0' ./src

pyinstaller \
  --onefile \
  --name sniparinject \
  --copy-metadata sniparinject \
  --distpath dist/executable \
  --workpath "${BUILD_PATH}/work" \
  --specpath "${BUILD_PATH}" \
  --noconfirm \
  script/executable-entry.py
deactivate

file dist/executable/sniparinject
dist/executable/sniparinject --version
