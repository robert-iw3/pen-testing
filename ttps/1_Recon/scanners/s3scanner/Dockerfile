FROM docker.io/golang:1.23-alpine AS builder

ARG VERSION=dev

RUN apk add --no-cache git

WORKDIR /S3Scanner

RUN git clone https://github.com/sa7mon/S3Scanner.git .
RUN go build -ldflags="-X 'main.version=${VERSION}'" -o /s3scanner .
RUN go build -o /mqingest ./cmd/mqingest/

FROM docker.io/alpine:latest

COPY --from=builder /s3scanner /
COPY --from=builder /mqingest /
ENV PATH="/"
ENTRYPOINT ["/s3scanner"]
