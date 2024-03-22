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
	RUST_LOG=INFO cargo watch -w src -x 'run -- -c ~/github/pingap/conf'

udeps:
	cargo +nightly udeps

bloat:
	cargo bloat --release --crates

outdated:
	cargo outdated

release:
	cargo build --release
	ls -lh target/release

hooks:
	cp hooks/* .git/hooks/
