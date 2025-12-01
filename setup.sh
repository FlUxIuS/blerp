#!/bin/bash

CURRENT_DIR=$(pwd)

# Setup Python Venv for MitM
python -m venv .venv
source .venv/bin/activate
pip install -r python-host/requirements.txt
deactivate

# Setup newt repositories
newt upgrade

# Patch mynewt core
cd "$CURRENT_DIR"
cd repos/apache-mynewt-core
git stash
git apply --reject --whitespace=fix "$CURRENT_DIR"/patches/core.patch
