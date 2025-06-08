FROM node:20-alpine AS webbuilder

COPY . /pingap
RUN apk update \
  && apk add git make \
  && cd /pingap \
  && make build-web

FROM rust:1.86.0 AS builder

ARG BUILD_ARGS=""

COPY --from=webbuilder /pingap /pingap

RUN apt update \
  && apt install -y cmake libclang-dev wget gnupg ca-certificates lsb-release protobuf-compiler --no-install-recommends
RUN rustup target list --installed
RUN cd /pingap \
  && cargo build --release ${BUILD_ARGS} \
  && ls -lh target/release

FROM ubuntu:24.04

COPY --from=builder /etc/ssl /etc/ssl
COPY --from=builder /pingap/target/release/pingap /usr/local/bin/pingap
COPY --from=builder /pingap/entrypoint.sh /entrypoint.sh

RUN mkdir -p /opt/pingap/conf

CMD ["pingap"]

ENTRYPOINT ["/entrypoint.sh"]
