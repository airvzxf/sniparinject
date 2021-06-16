#!/usr/bin/env bash
set -e

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}" || exit

cd ../

find ./ \
  -type f \
  -name "*.py" \
  -and \( \
    -not -path './build/*' \
    -and -not -path './dist/*' \
    -and -not -path './venv/*' \
    -and -not -path './script/*' \
    -and -not -path './htmlcov/*' \
  \) \
  -exec ./venv/bin/pylint '{}' +
