fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile protobuf files
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(
            &[
                "proto/common.proto",
                "proto/ethereum.proto",
                "proto/solana.proto",
            ],
            &["proto"],
        )?;
    
    // Re-run if proto files change
    println!("cargo:rerun-if-changed=proto/common.proto");
    println!("cargo:rerun-if-changed=proto/ethereum.proto");
    println!("cargo:rerun-if-changed=proto/solana.proto");
    
    Ok(())
}
