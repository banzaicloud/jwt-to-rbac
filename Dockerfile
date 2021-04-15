FROM golang:1.16.3-alpine AS builder

RUN apk add --update --no-cache ca-certificates git
RUN apk add build-base

RUN mkdir -p /build
WORKDIR /build

COPY go.* /build/
RUN go mod download
COPY . /build
RUN go install ./cmd

FROM alpine:3.13.5

COPY --from=builder /go/bin/cmd /usr/local/bin/jwt-to-rbac
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER 65534:65534

ENTRYPOINT ["/usr/local/bin/jwt-to-rbac"]
