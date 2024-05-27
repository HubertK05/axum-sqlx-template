alias r := run
alias w := watch

copy_config := if os_family() == "windows" { 
		'copy .\config\settings.example.toml .\config\settings.toml' 
	} else { 
		'cp ./config/settings.example.toml ./config/settings.toml' 
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
