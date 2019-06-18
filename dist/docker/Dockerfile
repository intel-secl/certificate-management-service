FROM registry.access.redhat.com/rhel7:7.5

COPY cms-*.bin /tmp/cms.bin
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /tmp/cms.bin && env TDS_NOSETUP=true /tmp/cms.bin && rm /tmp/cms.bin

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh"]