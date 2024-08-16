pub mod trace;

use trace::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the EVM environment
    let mut evm = Evm::new(
        None,
        "https://eth-mainnet.g.alchemy.com/v2/alVqJQCHT4wtrXuZQehBZaxd9MiFYgGk".to_string(), // Fork URL
        Some(20534500), // Block number
        1_000_000, // Gas limit
        None // Etherscan key, if needed
    ).await;

    // Set up a transaction
    let request = CallRawRequest {
        from: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".parse()?,
        to: "0xdAC17F958D2ee523a2206206994597C13D831ec7".parse()?,
        value: None,
        data: Some("0xa9059cbb0000000000000000000000003fc91a3afd70395cd496c647d5a6cc9d4b2b7fad".parse()?),
        access_list: None,
        format_trace: true, // Request trace formatting
    };

    // Execute the transaction and get the result
    let result = evm.call_raw(request).await?;

    // Output the result
    println!("Gas used: {}", result.gas_used);
    println!("Success: {}", result.success);
    println!("Logs: {:?}", result.logs);
    if let Some(trace) = result.formatted_trace {
        println!("Trace: {}", trace);
    }

    Ok(())
}