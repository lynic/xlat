FROM centos:7

ENV XLATCONF "/etc/xlat/config.yml"

COPY ./xlat /opt/

RUN mkdir -p /etc/xlat/ && \
    chmod a+x /opt/xlat && \
    yum install -y net-tools iproute && \
    yum clean all && \
    rm -rf /var/cache/yum


CMD ["/opt/xlat"]
