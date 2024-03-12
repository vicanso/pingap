lint:
	cargo clippy

fmt:
	cargo fmt

build-web:
	rm -rf dist \
	&& cd web \
	&& yarn install --network-timeout 600000 && yarn build \
	&& cp -rf dist ../

dev:
	cargo watch -w src -x 'run -- -c ~/github/pingap/conf'

udeps:
	cargo +nightly udeps

# 如果要使用需注释 profile.release 中的 strip
bloat:
	cargo bloat --release --crates

outdated:
	cargo outdated

release:
	cargo build --release
	ls -lh target/release

hooks:
	cp hooks/* .git/hooks/
