# Go Certificate Management Service

### Build
```console
> make all
```

Installer Bin will be available in out/cms-*.bin
Exportable docker image will be available in out/ as well


### Deploy
```console
> ./cms-*.bin
```

OR

```console
> docker-compose -f dist/docker/docker-compose.yml up
```

### Config
Add / Update following configuration in cms.env

    WLS_LOGLEVEL=DEBUG


### Manage service
* Start service
    * cms start
* Stop service
    * cms stop
* Restart service
    * cms restart
* Status of service
    * cms status

### v1.0/develop CI Status
[![v1.0/develop pipeline status](https://gitlab.devtools.intel.com/sst/isecl/certificate-management-service/badges/v1.0/develop/pipeline.svg)](https://gitlab.devtools.intel.com/sst/isecl/certificate-management-service/commits/v1.0/develop)
[![v1.0/develop coverage report](https://gitlab.devtools.intel.com/sst/isecl/certificate-management-service/badges/v1.0/develop/coverage.svg)](https://gitlab.devtools.intel.com/sst/isecl/certificate-management-service/commits/v1.0/develop)


