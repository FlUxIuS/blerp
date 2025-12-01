#!/bin/bash

CURRENT_DIR=$(pwd)

cd repos/apache-mynewt-nimble
git stash
git checkout 675452b628

git apply --reject --whitespace=fix "$CURRENT_DIR"/patches/blerp-fixes.patch
