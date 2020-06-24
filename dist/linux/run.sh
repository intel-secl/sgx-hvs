#!/bin/bash
make clean
shvs uninstall
make installer
./out/shvs-v0.0.0.bin
./test.sh hosts
