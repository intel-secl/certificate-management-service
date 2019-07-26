#!/bin/bash

# READ .env file
echo PWD IS $(pwd)
if [ -f ~/cms.env ]; then
    echo Reading Installation options from `realpath ~/cms.env`
    env_file=~/cms.env
elif [ -f ../cms.env ]; then
    echo Reading Installation options from `realpath ../cms.env`
    env_file=../cms.env
fi

if [ -n $env_file ]; then
    source $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
else
    echo No .env file found
    CMS_NOSETUP="true"
fi

if [[ $EUID -ne 0 ]]; then 
    echo "This installer must be run as root"
    exit 1
fi

echo "Setting up Certificate Management Service Linux User..."
id -u cms 2> /dev/null || useradd cms

echo "Installing Certificate Management Service..."

COMPONENT_NAME=cms
PRODUCT_HOME=/opt/$COMPONENT_NAME
BIN_PATH=$PRODUCT_HOME/bin
DB_SCRIPT_PATH=$PRODUCT_HOME/cacerts
LOG_PATH=/var/log/$COMPONENT_NAME/
CONFIG_PATH=/etc/$COMPONENT_NAME

mkdir -p $BIN_PATH && chown cms:cms $BIN_PATH/
cp $COMPONENT_NAME $BIN_PATH/ && chown cms:cms $BIN_PATH/*
chmod 750 $BIN_PATH/*
ln -sfT $BIN_PATH/$COMPONENT_NAME /usr/bin/$COMPONENT_NAME

mkdir -p $DB_SCRIPT_PATH && chown cms:cms $DB_SCRIPT_PATH/

# Create configuration directory in /etc
mkdir -p $CONFIG_PATH && chown cms:cms $CONFIG_PATH
chmod 700 $CONFIG_PATH
chmod g+s $CONFIG_PATH

# Create jwt certs directory in config
mkdir -p $CONFIG_PATH/jwt && chown cms:cms $CONFIG_PATH/jwt
chmod 700 $CONFIG_PATH/jwt
chmod g+s $CONFIG_PATH/jwt

mkdir -p $CONFIG_PATH/root-ca && chown cms:cms $CONFIG_PATH/root-ca
chmod 700 $CONFIG_PATH/root-ca
chmod g+s $CONFIG_PATH/root-ca

# Create logging dir in /var/log
mkdir -p $LOG_PATH && chown cms:cms $LOG_PATH
chmod 761 $LOG_PATH
chmod g+s $LOG_PATH

# Install systemd script
cp cms.service $PRODUCT_HOME && chown cms:cms $PRODUCT_HOME/cms.service && chown cms:cms $PRODUCT_HOME

# Enable systemd service
systemctl disable cms.service > /dev/null 2>&1
systemctl enable $PRODUCT_HOME/cms.service
systemctl daemon-reload

# check if CMS_NOSETUP is defined
if [ "${CMS_NOSETUP,,}" == "true" ]; then
    echo "CMS_NOSETUP is true, skipping setup"
    echo "Installation completed successfully!"
else 
    $COMPONENT_NAME setup all
    SETUPRESULT=$?
    if [ ${SETUPRESULT} == 0 ]; then 
        systemctl start $COMPONENT_NAME
        echo "Waiting for daemon to settle down before checking status"
        sleep 3
        systemctl status $COMPONENT_NAME 2>&1 > /dev/null
        if [ $? != 0 ]; then
            echo "Installation completed with Errors - $COMPONENT_NAME daemon not started."
            echo "Please check errors in syslog using \`journalctl -u $COMPONENT_NAME\`"
            exit 1
        fi
        echo "$COMPONENT_NAME daemon is running"
        echo "Installation completed successfully!"
    else 
        echo "Installation completed with errors"
    fi
fi
