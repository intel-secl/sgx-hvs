#!/bin/bash
sgx-host-verification-service uninstall
make clean 
make installer || exit 1
./out/sgx-host-verification-service-v0.0.0.bin || exit 1
#./test.sh
