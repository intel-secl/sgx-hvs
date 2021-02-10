/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#!/bin/bash

USER_ID=$(id -u)
LOG_PATH=/var/log/shvs
CONFIG_PATH=/etc/shvs
CERTS_DIR=${CONFIG_PATH}/certs
TRUSTED_CERTS=${CERTS_DIR}/trustedca
CERTDIR_TRUSTEDJWTCERTS=${CERTS_DIR}/trustedjwt
DB_SCRIPT_PATH=/opt/shvs/dbscripts


if [ ! -f $CONFIG_PATH/.setup_done ]; then
  for directory in $LOG_PATH $CONFIG_PATH $CERTS_DIR $TRUSTED_CERTS $CERTDIR_TRUSTEDJWTCERTS; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chown -R $USER_ID:$USER_ID $directory
    chmod 700 $directory
  done
  shvs setup all
  if [ $? -ne 0 ]; then
    exit 1
  fi
  touch $CONFIG_PATH/.setup_done
fi
if [ ! -z $SETUP_TASK ]; then
  IFS=',' read -ra ADDR <<< "$SETUP_TASK"
  for task in "${ADDR[@]}"; do
    shvs setup $task --force
    if [ $? -ne 0 ]; then
      exit 1
    fi
  done
fi
shvs run
