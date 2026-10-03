FROM node:24-alpine AS webbuilder

COPY . /pingap
RUN apk update \
  && apk add git make \
  && cd /pingap \
  && make build-web

# Release toolchain - keep in step with the `toolchain:` pins in
# .github/workflows/publish.yml. The Debian release is pinned so it moves only
# together with the runtime stage below.
FROM rust:1.98.1-trixie AS builder

ARG BUILD_ARGS=""

COPY --from=webbuilder /pingap /pingap

RUN apt update \
  && apt install -y cmake libclang-dev wget gnupg ca-certificates lsb-release protobuf-compiler --no-install-recommends
RUN rustup target list --installed
RUN cd /pingap \
  && cargo build --release ${BUILD_ARGS} \
  && ls -lh target/release

# Opt-in variant (`--target distroless`). Keep it above the Debian stage:
# a plain `docker build .` builds the last stage, the default image.
FROM gcr.io/distroless/cc-debian13 AS distroless

COPY --from=builder /pingap/target/release/pingap /usr/local/bin/pingap

CMD ["pingap"]

# Same Debian release as the builder, so the binary runs on the glibc it was
# linked against.
FROM debian:trixie-slim

COPY --from=builder /etc/ssl /etc/ssl
COPY --from=builder /pingap/target/release/pingap /usr/local/bin/pingap
COPY --from=builder /pingap/entrypoint.sh /entrypoint.sh

RUN mkdir -p /opt/pingap/conf

CMD ["pingap"]

ENTRYPOINT ["/entrypoint.sh"]
