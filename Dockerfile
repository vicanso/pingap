FROM node:20-alpine as webbuilder

COPY . /pingap
RUN apk update \
  && apk add git make \
  && cd /pingap \
  && make build-web

FROM rust as builder

COPY --from=webbuilder /pingap /pingap

RUN apt update \
  && apt install -y cmake libclang-dev wget gnupg ca-certificates lsb-release --no-install-recommends protobuf-compiler
RUN rustup target list --installed
RUN cd /pingap \
  && make release

FROM alpine

EXPOSE 7001

# tzdata 安装所有时区配置或可根据需要只添加所需时区

RUN addgroup -g 1000 rust \
  && adduser -u 1000 -G rust -s /bin/sh -D rust \
  && apk add --no-cache ca-certificates tzdata

COPY --from=builder /pingap/target/release/pingap /usr/local/bin/pingap
COPY --from=builder /pingap/entrypoint.sh /entrypoint.sh

USER rust

WORKDIR /home/rust

RUN mkdir -p /home/rust/pingap/conf


CMD ["pingap", "-c", "/home/rust/conf"]

ENTRYPOINT ["/entrypoint.sh"]
