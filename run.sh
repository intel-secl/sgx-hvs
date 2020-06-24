#!/bin/bash
shvs uninstall
make clean 
make installer || exit 1
./out/shvs-v0.0.0.bin || exit 1
#./test.sh
