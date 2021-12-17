FROM alpine:3.6 as alpine
RUN apk add -U --no-cache ca-certificates

FROM docker:20.10.12-dind

RUN apk --update add \
    curl

# required to install scanning
RUN mkdir -p ~/.docker/cli-plugins && \
    curl https://github.com/docker/scan-cli-plugin/releases/download/v0.12.0/docker-scan_linux_amd64 -L -s -S -o ~/.docker/cli-plugins/docker-scan &&\
    chmod +x ~/.docker/cli-plugins/docker-scan

ENV GODEBUG netdns=go
ENV DOCKER_HOST=unix:///var/run/docker.sock

COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ADD release/linux/amd64/plugin /bin/

ENTRYPOINT ["/usr/local/bin/dockerd-entrypoint.sh", "/bin/plugin"]