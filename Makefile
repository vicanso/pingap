lint:
	typos
	cargo clippy --all-targets --all -- --deny=warnings
lint-full:
	typos
	cargo clippy --features=full --all-targets --all -- --deny=warnings

fmt:
	cargo fmt

build-web:
	rm -rf dist \
	&& cd web \
	&& npm install && npm run  build \
	&& cp -rf dist ../

update-shadcn:
	cd web && for file in src/components/ui/*.tsx; do npx shadcn@latest add -y -o $(basename "$file" .tsx); done

bench:
	cargo bench

dev:
	RUST_LOG=INFO cargo watch -w src -x 'run -- -c=~/github/pingap/conf/pingap.toml'

devtest:
	RUST_LOG=INFO cargo watch -w src -x 'run -- -c=~/tmp/pingap?separation --admin=pingap:123123@127.0.0.1:3018 --autoreload'

devetcd:
	RUST_LOG=INFO cargo watch -w src -x 'run -- -c="etcd://127.0.0.1:2379/pingap?timeout=10s&connect_timeout=5s" --admin=127.0.0.1:3018 --autoreload'


udeps:
	cargo +nightly udeps

msrv:
	cargo msrv list


bloat:
	cargo bloat --release --crates

outdated:
	cargo outdated

unused-features:
	unused-features analyze

test:
	cargo test --features=full

cov:
	cargo llvm-cov --html --open

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

perf:
	cargo build --profile=release-perf --features=perf
	ls -lh target/release-perf
pyro:
	cargo build --profile=release-perf --features=pyro
	ls -lh target/release-perf

publish:
	make build-web
	cargo publish --registry crates-io --no-verify

hooks:
	cp hooks/* .git/hooks/

version:
	git cliff --unreleased --tag 0.9.8 --prepend CHANGELOG.md
