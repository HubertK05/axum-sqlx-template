alias r := run
alias w := watch

_default:
	@just --list

# Standard compilation run
run:
	cargo run

# hot-reload comiplation without socket interrupt
watch:
	systemfd --no-pid -s 3000 -- cargo watch -x run

# Generate query metadata to support offline compile-time verification
sqlx:
	cargo sqlx prepare --workspace -- --tests

# Install development dependencies
install:
	cargo install systemfd cargo-watch typeshare-cli sqlx-cli
