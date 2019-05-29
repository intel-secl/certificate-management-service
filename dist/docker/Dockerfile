FROM centos:latest

COPY cms-*.bin /tmp/cms
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN env CMS_NOSETUP=true && chmod +x /tmp/cms && /tmp/cms && rm /tmp/cms

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]
