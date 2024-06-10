fn main() -> Result<(), Box<dyn std::error::Error>> {
    // When building in docs.rs, we want to set SQLX_OFFLINE mode to true
    if std::env::var_os("DOCS_RS").is_some() {
        println!("cargo:rustc-env=SQLX_OFFLINE=true");
    }
    tonic_build::compile_protos("proto/helloworld.proto")?;
    Ok(())
}
