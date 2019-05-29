#!/bin/bash

# READ .env file from ~/cms.env or ./cms.env
if [ -f ~/cms.env ]; then 
    echo Reading Installation options from `realpath ~/cms.env`
    source ~/cms.env
elif [ -f ./cms.env ]; then
    echo Reading Installation options from `realpath ./cms.env`
        source ./cms.env
fi

# assert that installer is ran as root
if [[ $EUID -ne 0 ]]; then
   echo "This installer must be run as root" 
   exit 1
fi

#CMS basic properties
export CMS_USERNAME
export CMS_PASSWORD
export CMS_NOSETUP #Default is false

#CMS certificate specific properties
export CMS_CA_CERT_VALIDITY #Default is 5 years
export CMS_ORGANIZATION
export CMS_LOCALITY
export CMS_PROVINCE
export CMS_COUNTRY
export CMS_CA_CERT_SAN_LIST
export CMS_CA_CERT_SIGNING_EXTENSIONS


echo Creating Certificate Management Service User ...
id -u cms 2> /dev/null || useradd cms

echo Installing Workload Service ... 
# Make the dir to store bin files
mkdir -p /opt/cms/bin
cp cms /opt/cms/bin/cms
ln -s /opt/cms/bin/cms /usr/local/bin/cms
chmod +x /usr/local/bin/cms
chmod +s /usr/local/bin/cms 
chown cms:cms /usr/local/bin/cms

# Create configuration directory in /etc
mkdir -p /etc/cms 
chown cms:cms /etc/cms
# Create PID file directory in /var/run
mkdir -p /var/run/cms
chown cms:cms /var/run/cms
# Create arbitrary data repository in /var/lib
mkdir -p /var/lib/cms
chown wls:wls /var/lib/cms
# Create logging directory in /var/log
mkdir -p /var/log/cms
chown wls:wls /var/log/cms

# install system service only if not in a docker container
echo Installation complete!

echo Running setup tasks ...
cms setup
SETUP_RESULT=$?

# now run it
if [ ${SETUP_RESULT} == 0 ]; then
    cms start
fi