FROM golang:1.11-alpine AS builder

RUN apk add --update --no-cache ca-certificates make git curl mercurial

ARG PACKAGE=github.com/banzaicloud/jwt-to-rbac

RUN mkdir -p /go/src/${PACKAGE}
WORKDIR /go/src/${PACKAGE}

COPY . /go/src/${PACKAGE}
RUN BUILD_DIR=/tmp make build-release

FROM alpine:3.7

RUN apk add --update libcap && rm -rf /var/cache/apk/*

COPY --from=builder /tmp/jwt-to-rbac /usr/local/bin/jwt-to-rbac
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

RUN mkdir -p /etc/jwt-to-rbac
COPY config/config.yaml /etc/jwt-to-rbac/config.yaml
ENV CONFIG_DIR=/etc/jwt-to-rbac

RUN adduser -D jwt-to-rbac
RUN setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/jwt-to-rbac
USER jwt-to-rbac

ENTRYPOINT ["/usr/local/bin/jwt-to-rbac"]
