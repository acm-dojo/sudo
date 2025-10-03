#!/bin/bash

dojo-g++ ./bash.c -o bash
dojo-g++ ./python.c -o python

git add bash python
git commit -m "chore: recompile binaries with dojo-g++"