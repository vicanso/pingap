lint:
	typos
	cargo clippy --features=full --all-targets --all -- --deny=warnings

fmt:
	cargo fmt --all

build-web:
	rm -rf dist \
	&& cd web \
	&& npm install && npm run  build \
	&& cp -rf dist ../


bench-all:
	cargo bench -p pingap-core
	cargo bench -p pingap-logger
	cargo bench -p pingap-location

bench:
	cargo bench

dev:
	bacon run --  --features=full -- -c="~/tmp/pingap?separation=true&enable_history=true" --admin=pingap:123123@127.0.0.1:3018 --autoreload

devetcd:
	bacon run -- -- -c="etcd://127.0.0.1:2379/pingap?timeout=10s&connect_timeout=5s&enable_history=true" --admin=127.0.0.1:3018 --autoreload

mermaid:
	cargo run --bin generate-mermaid

udeps:
	cargo +nightly udeps

msrv:
	cargo msrv list


bloat:
	cargo bloat --release --crates --bin pingap

outdated:
	cargo outdated

unused-features:
	unused-features analyze

test:
	cargo test --workspace --features=full

cov:
	cargo llvm-cov --workspace --html --open

release:
	cargo build --release
	ls -lh target/release

release-full:
	cargo build --release --features=full
	ls -lh target/release


release-all:
	cargo build --release --features=full
	mv target/release/pingap target/release/pingap-full
	cargo build --release
	ls -lh target/release

release-perf:
	cargo build --profile=release-perf --features=perf
	ls -lh target/release-perf
release-pyro:
	cargo build --profile=release-perf --features=pyro
	ls -lh target/release-perf

publish:
	make build-web
	cargo publish --registry crates-io --no-verify

hooks:
	cp hooks/* .git/hooks/

version:
	git cliff --unreleased --tag v0.12.0 --prepend CHANGELOG.md
