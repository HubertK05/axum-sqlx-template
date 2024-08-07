alias r := run
alias w := watch

copy_config := if os_family() == "windows" {
		'copy /-y .\config\settings.example.toml .\config\settings.toml & copy /-y .\.env.example .\.env'
	} else {
		'cp -i ./config/settings.example.toml ./config/settings.toml ; cp -i ./.env.example ./.env'
	}

_default:
	@just --list


# First time project initialisation
[no-cd]
@bootstrap:
	echo "Preparing project" && \
	echo "Generating configuration files" && \
	{{ copy_config }} ; \
	echo "Generating JWT keys" && \
	just genkeys && \
	echo "Succesfully generated JWT keys" && \
	echo "Creating database" && \
	sqlx database create && \
	echo "Running migrations" && \
	sqlx migrate run && \
	echo "Configuration complete"

# Standard compilation run
run:
	cargo run

# hot-reload comiplation without socket interrupt
[no-cd]
watch:
	systemfd --no-pid -s 3000 -- cargo watch -x run || \
	cargo install systemfd cargo-watch && \
	systemfd --no-pid -s 3000 -- cargo watch -x run

# Generate query metadata to support offline compile-time verification
[no-cd]
prepare:
	cargo sqlx prepare --workspace -- --tests

# Install development dependencies
install:
	cargo install systemfd cargo-watch typeshare-cli sqlx-cli --locked

# Generate JWT keys
[no-cd]
@genkeys:
    mkdir -p ./keys && \
    openssl genpkey -algorithm Ed25519 -out ./keys/jwt_access_private_key.pem && \
    openssl pkey -in ./keys/jwt_access_private_key.pem -pubout -out ./keys/jwt_access_public_key.pem && \
    openssl genpkey -algorithm Ed25519 -out ./keys/jwt_refresh_private_key.pem && \
    openssl pkey -in ./keys/jwt_refresh_private_key.pem -pubout -out ./keys/jwt_refresh_public_key.pem
