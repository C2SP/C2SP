FROM golang:1.26.0-alpine3.23 AS builder

COPY . src
WORKDIR src
ENV CGO_ENABLED=0
ENV GOTOOLCHAIN=auto
RUN go install -trimpath

FROM alpine:3.23

COPY --from=builder /go/bin/website /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/website"]
