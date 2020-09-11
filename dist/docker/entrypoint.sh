#!/bin/bash

SERVICE_USERNAME=cms
LOG_PATH=/var/log/cms
CONFIG_PATH=/etc/cms
ROOT_CA_DIR=${CONFIG_PATH}/root-ca
INTERMEDIATE_CA_DIR=${CONFIG_PATH}/intermediate-ca
CERTDIR_TRUSTEDJWTCERTS=${CONFIG_PATH}/jwt

if [ ! -f $CONFIG_PATH/.setup_done ]; then
  for directory in $LOG_PATH $CONFIG_PATH $CERTDIR_TRUSTEDJWTCERTS $ROOT_CA_DIR $INTERMEDIATE_CA_DIR; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chown -R $SERVICE_USERNAME:$SERVICE_USERNAME $directory
    chmod 700 $directory
    chmod g+s $directory
  done
  cms setup all
  if [ $? -ne 0 ]; then
    exit 1
  fi
  touch $CONFIG_PATH/.setup_done
fi

cms run
