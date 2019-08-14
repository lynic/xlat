FROM centos:7

ENV XLATCONF "/etc/xlat/config.yml"

COPY ./xlat /opt/

RUN mkdir -p /etc/xlat/ && \
    chmod a+x /opt/xlat


CMD ["/opt/xlat"]
