FROM golang:1.24.1-alpine3.21 AS builder
ENV GOTOOLCHAIN=auto
COPY . /go/src/maintainers
WORKDIR /go/src/maintainers
RUN go install -trimpath .

FROM alpine:3.21
COPY --from=builder /go/bin/maintainers /usr/local/bin/maintainers
ENTRYPOINT ["/usr/local/bin/maintainers"]
