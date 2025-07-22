# syntax=docker/dockerfile:1
# legba: A multiprotocol credentials bruteforcer / password sprayer and enumerator built with Rust.

# compiling stage
FROM docker.io/rust:bookworm as builder

RUN \
	apt-get update ; \
	apt-get install -y \
		libsmbclient-dev \
		libssl-dev \
		ca-certificates \
		cmake \
		git; \
	cargo install legba

###################
FROM docker.io/debian:bookworm
RUN apt-get update && apt-get install -y libsmbclient libssl-dev ca-certificates
COPY --from=builder /usr/local/cargo/bin/legba /usr/bin/
CMD [ "bash" ]
# legba -h
# https://github.com/evilsocket/legba/wiki/Usage-and-Main-Options

