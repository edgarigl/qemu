#!/bin/sh
#
# Script to create patches for Zero ASIC's yocto SDK.
#

# Diff switchboard/cpp/ with root commit.
git -C switchboard/ diff --src-prefix=a/switchboard/ --dst-prefix=b/switchboard/ 17e98111fa1445e2422d8121d59c6b3b4d8545dd -- cpp/

git diff --submodule=log v7.2.0

