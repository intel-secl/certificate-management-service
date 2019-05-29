GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)

.PHONY: cms installer all clean

cms:
	env GOOS=linux go build -ldflags "-X intel/isecl/cms/version.Version=$(VERSION) -X intel/isecl/cms/version.GitHash=$(GITCOMMIT)" -o out/cms

installer: cms
	mkdir -p out/cms
	cp dist/linux/install.sh out/cms/install.sh && chmod +x out/cms/install.sh
	cp out/cms out/cms/cms
	makeself out/cms out/cms-$(VERSION).bin "Certificate Management Service $(VERSION)" ./install.sh 

all: installer

clean:
	rm -rf out/