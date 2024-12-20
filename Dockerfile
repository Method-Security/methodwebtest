# Dockerfile used as distribution for the methodwebtest CLI in Tool container format
FROM alpine:3.20

ARG CLI_NAME="methodwebtest"
ARG TARGETARCH

RUN apk update && apk --no-cache add ca-certificates bash git

# Setup Method Directory Structure
RUN \
  mkdir -p /opt/method/${CLI_NAME}/ && \
  mkdir -p /opt/method/${CLI_NAME}/var/data && \
  mkdir -p /opt/method/${CLI_NAME}/var/data/tmp && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf/paths && \
  mkdir -p /opt/method/${CLI_NAME}/var/log && \
  mkdir -p /opt/method/${CLI_NAME}/service/bin && \
  mkdir -p /mnt/output

COPY configs/*                     /opt/method/${CLI_NAME}/var/conf/
COPY configs/paths/*               /opt/method/${CLI_NAME}/var/conf/paths/

COPY ${CLI_NAME} /opt/method/${CLI_NAME}/service/bin/${CLI_NAME}

RUN \
  adduser --disabled-password --gecos '' method && \
  chown -R method:method /opt/method/${CLI_NAME}/ && \
  chown -R method:method /mnt/output

USER method

WORKDIR /opt/method/${CLI_NAME}/

ENV PATH="/opt/method/${CLI_NAME}/service/bin:${PATH}"
ENTRYPOINT [ "methodwebtest" ]