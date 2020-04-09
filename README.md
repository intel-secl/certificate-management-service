# Certificate Management Service

`Certificate Management Service` is a web service whose purpose is to manage all Certificates in ecosystem

## Key features
- Provides self signed Root CA
- Sign rest of the certificates in ecosystem by Root CA
- RESTful APIs for easy and versatile access to above features

## System Requirements
- RHEL 8.1
- Epel 8 Repo
- Proxy settings if applicable

## Software requirements
- git
- makeself
- `go` version >= `go1.12.1` & <= `go1.14.1`

# Step By Step Build Instructions

## Install required shell commands

### Install tools from `yum`
```shell
sudo yum install -y git wget makeself
```

### Install `go` version >= `go1.12.1` & <= `go1.14.1`
The `Certificate Management Service` requires Go version 1.12.1 that has support for `go modules`. The build was validated with the latest version go1.14.1 of `go`. It is recommended that you use go1.14.1 version of `go`. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.14.1.linux-amd64.tar.gz
tar -xzf go1.14.1.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build Certificate Management service

- Git clone the Certificate Management service
- Run scripts to build the Certificate Management service

```shell
git clone https://github.com/intel-secl/certificate-management-service.git
cd certificate-management-service
make all
```

### Deploy
```console
> ./cms-*.bin
```

OR

```console
> docker-compose -f dist/docker/docker-compose.yml up
```

### Manage service
* Start service
    * cms start
* Stop service
    * cms stop
* Restart service
    * cms restart
* Status of service
    * cms status

# Third Party Dependencies

## Certificate Management Service

### Direct dependencies

| Name        | Repo URL                    | Minimum Version Required           |
| ----------- | --------------------------- | :--------------------------------: |
| uuid        | github.com/google/uuid      | v1.1.1                             |
| handlers    | github.com/gorilla/handlers | v1.4.0                             |
| mux         | github.com/gorilla/mux      | v1.7.0                             |
| gorm        | github.com/jinzhu/gorm      | v1.9.2                             |
| logrus      | github.com/sirupsen/logrus  | v1.3.0                             |
| testify     | github.com/stretchr/testify | v1.3.0                             |
| crypto      | golang.org/x/crypto         | v0.0.0-20190219172222-a4c6cb3142f2 |
| yaml.v2     | gopkg.in/yaml.v2            | v2.2.2                             |
| authservice | intel/isecl/authservice     | v0.0.0	                         |
| common      | intel/isecl/lib/common      | v1.0.0-Beta                        |

### Indirect Dependencies

| Repo URL                     | Minimum version required           |
| -----------------------------| :--------------------------------: |
| github.com/jinzhu/inflection | v0.0.0-20180308033659-04140366298a |
| github.com/lib/pq            | v1.0.0                             |

*Note: All dependencies are listed in go.mod*

# Links
https://01.org/intel-secl/cms
