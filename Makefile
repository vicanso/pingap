lint:
	cargo clippy

fmt:
	cargo fmt

build-web:
	rm -rf dist \
	&& cd web \
	&& yarn install --network-timeout 600000 && yarn build \
	&& cp -rf dist ../

bench:
	cargo bench

dev:
	RUST_LOG=INFO cargo watch -w src -x 'run -- -c=~/github/pingap/conf/pingap.toml'

devtest:
	RUST_LOG=INFO cargo watch -w src -x 'run -- -c=~/tmp/pingap.toml --admin=127.0.0.1:3018'


udeps:
	cargo +nightly udeps

msrv:
	cargo msrv verify


bloat:
	cargo bloat --release --crates

outdated:
	cargo outdated

test:
	cargo test

release:
	cargo build --release
	ls -lh target/release

publish:
	make build-web
	cargo publish --registry crates-io --no-verify

hooks:
	cp hooks/* .git/hooks/
