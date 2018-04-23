#!/bin/sh

export PYTHONPATH=$PWD
rlwrap gdb -x start.gdb
