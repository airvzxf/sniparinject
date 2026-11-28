#!/usr/bin/env bash
# Run the executable built by executable-build.bash on a small capture file
# and check the packet lines that it prints.
set -ev

CURRENT_PATH=$(dirname "${0}")
cd "${CURRENT_PATH}/.." || exit

EXECUTABLE=dist/executable/sniparinject
${EXECUTABLE} --version
output=$(${EXECUTABLE} test/data/executable/settings.yml | sed 's/\x1b\[[0-9;]*m//g')
echo "${output}"
grep -qxF -- '--> Scenario change |' <<< "${output}"
grep -qxF -- '<-- NPC Monster Check | ID 0x0000000f |' <<< "${output}"

if ${EXECUTABLE} test/data/executable/missing.yml; then
  echo 'A missing settings file must fail.'
  exit 1
fi
