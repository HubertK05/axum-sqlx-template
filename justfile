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
bootstrap:
	{{ copy_config }}

# Standard compilation run
run:
	cargo run

# hot-reload comiplation without socket interrupt
watch:
	systemfd --no-pid -s 3000 -- cargo watch -x run

# Generate query metadata to support offline compile-time verification
prepare:
	cargo sqlx prepare --workspace -- --tests

# Install development dependencies
install:
	cargo install systemfd cargo-watch typeshare-cli sqlx-cli --locked
