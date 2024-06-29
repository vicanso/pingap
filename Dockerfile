FROM node:20-alpine as webbuilder

COPY . /pingap
RUN apk update \
  && apk add git make \
  && cd /pingap \
  && make build-web

FROM rust as builder

COPY --from=webbuilder /pingap /pingap

RUN apt update \
  && apt install -y cmake libclang-dev wget gnupg ca-certificates lsb-release protobuf-compiler --no-install-recommends
RUN rustup target list --installed
RUN cd /pingap \
  && make release

FROM ubuntu:22.04

EXPOSE 7001

COPY --from=builder /pingap/target/release/pingap /usr/local/bin/pingap
COPY --from=builder /pingap/entrypoint.sh /entrypoint.sh

RUN mkdir -p /opt/pingap/conf

CMD ["pingap", "-c", "/opt/pingap/conf", "--autoreload"]

ENTRYPOINT ["/entrypoint.sh"]
