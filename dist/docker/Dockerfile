FROM registry.access.redhat.com/ubi7-init:7.6

COPY cms-*.bin /tmp/cms.bin
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /tmp/cms.bin && env CMS_NOSETUP=true /tmp/cms.bin && rm /tmp/cms.bin

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh"]
