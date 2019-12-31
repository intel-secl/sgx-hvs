#!/bin/bash
make clean
sgx-host-verification-service uninstall
make installer
./out/sgx-host-verification-service-v0.0.0.bin
./test.sh hosts
