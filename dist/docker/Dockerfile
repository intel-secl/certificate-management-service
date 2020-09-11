FROM centos:8

RUN useradd -u 1001 --comment "Certificate Management Service" --home /opt/cms  --shell /bin/false cms

RUN mkdir -p /opt/cms/bin
COPY cms /opt/cms/bin/
RUN ln -sfT  /opt/cms/bin/cms /usr/bin/cms

COPY entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh"]
