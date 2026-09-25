FROM golang:1.27.1-alpine AS builder

RUN apk add --update --no-cache ca-certificates git
RUN apk add build-base

RUN mkdir -p /build
WORKDIR /build

COPY go.* /build/
RUN go mod download
COPY . /build
RUN CGO_ENABLED=0 go install ./cmd

FROM gcr.io/distroless/static-debian12

COPY --from=builder /go/bin/cmd /usr/local/bin/jwt-to-rbac

USER 65534:65534

ENTRYPOINT ["/usr/local/bin/jwt-to-rbac"]
