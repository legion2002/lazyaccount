use std::collections::HashMap;

use foundry_config::Chain;
use foundry_evm::backend::Backend;
use foundry_evm::executors::EvmError;
use foundry_evm::executors::Executor;
use foundry_evm::executors::ExecutorBuilder;
use foundry_evm::fork::CreateFork;
use foundry_evm::opts::EvmOpts;

use foundry_evm::traces::identifier::{EtherscanIdentifier, SignaturesIdentifier};
use foundry_evm::traces::TraceWriter;
use foundry_evm::traces::{
    CallTrace, CallTraceArena, CallTraceDecoder, CallTraceDecoderBuilder, CallTraceNode,
};

use revm::interpreter::InstructionResult;
use revm::primitives::AccessListItem;
use revm::primitives::Log;
use revm::primitives::{Address, Bytes, Env, U256};

#[derive(Debug, Clone)]
pub struct CallRawRequest {
    pub from: Address,
    pub to: Address,
    pub value: Option<U256>,
    pub data: Option<Bytes>,
    pub access_list: Option<Vec<AccessListItem>>,
    pub format_trace: bool,
}

#[derive(Debug, Clone)]
pub struct CallRawResult {
    pub gas_used: u64,
    pub block_number: u64,
    pub success: bool,
    pub trace: Option<CallTraceArena>,
    pub logs: Vec<Log>,
    pub exit_reason: InstructionResult,
    pub return_data: Bytes,
    pub formatted_trace: Option<String>,
}

fn convert_call_trace_node(item: CallTraceNode) -> CallTrace {
    CallTrace {
        value: item.trace.value,
        depth: item.trace.depth,
        success: item.trace.success,
        caller: item.trace.caller,
        address: item.trace.address,
        maybe_precompile: item.trace.maybe_precompile,
        selfdestruct_refund_target: item.trace.selfdestruct_refund_target,
        selfdestruct_transferred_value: item.trace.selfdestruct_transferred_value,
        kind: item.trace.kind,
        data: item.trace.data,
        output: item.trace.output,
        gas_used: item.trace.gas_used,
        gas_limit: item.trace.gas_limit,
        status: item.trace.status,
        steps: item.trace.steps,
        decoded: item.trace.decoded,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StorageOverride {
    pub slots: HashMap<U256, U256>,
    pub diff: bool,
}

pub struct Evm {
    executor: Executor,
    decoder: CallTraceDecoder,
    etherscan_identifier: Option<EtherscanIdentifier>,
}

impl Evm {
    pub async fn new(
        env: Option<Env>,
        fork_url: String,
        fork_block_number: Option<u64>,
        gas_limit: u64,
        etherscan_key: Option<String>,
    ) -> Self {
        let evm_opts = EvmOpts {
            fork_url: Some(fork_url.clone()),
            fork_block_number,
            env: foundry_evm::opts::Env {
                chain_id: None,
                code_size_limit: None,
                gas_price: Some(0),
                gas_limit: u64::MAX,
                ..Default::default()
            },
            memory_limit: foundry_config::Config::default().memory_limit,
            ..Default::default()
        };

        let fork_opts = CreateFork {
            url: fork_url,
            enable_caching: true,
            env: evm_opts.evm_env().await.unwrap(),
            evm_opts,
        };

        let db = Backend::spawn(Some(fork_opts.clone()));

        let builder = ExecutorBuilder::default().gas_limit(gas_limit);

        let executor = builder.build(env.unwrap_or(fork_opts.env.clone()), db);

        let foundry_config = foundry_config::Config {
            etherscan_api_key: etherscan_key,
            ..Default::default()
        };

        let chain: Chain = fork_opts.env.cfg.chain_id.into();
        let etherscan_identifier =
            EtherscanIdentifier::new(&foundry_config, Some(chain)).unwrap_or_default();
        let decoder = CallTraceDecoderBuilder::new().with_verbosity(5);

        let decoder = if let Ok(identifier) =
            SignaturesIdentifier::new(foundry_config::Config::foundry_cache_dir(), false)
        {
            decoder.with_signature_identifier(identifier)
        } else {
            decoder
        };

        Evm {
            executor,
            decoder: decoder.build(),
            etherscan_identifier,
        }
    }

    pub async fn call_raw(&mut self, call: CallRawRequest) -> Result<CallRawResult, EvmError> {
        self.set_access_list(call.access_list)?;

        // Execute the call and unwrap the result only once
        let res = self
            .executor
            .call_raw(
                call.from,
                call.to,
                call.data.unwrap_or_default(),
                call.value.unwrap_or_default(),
            )
            .map_err(|err| {
                dbg!(&err);
                EvmError::Eyre(err)
            })
            .unwrap(); // Call unwrap once here

        println!("{:?}", res);

        // Extract values from `res`
        let gas_used = res.gas_used;
        let block_number = res.env.block.number.to();
        let success = !res.reverted;
        let trace = res.traces;
        let logs = res.logs;
        let exit_reason = res.exit_reason;
        let return_data = res.result;

        let formatted_trace = if call.format_trace {
            let mut trace_writer = TraceWriter::new(Vec::<u8>::new());
            for trace in &trace {
                // Use trace from destructured value
                if let Some(identifier) = &mut self.etherscan_identifier {
                    self.decoder.identify(trace, identifier);
                }
                trace_writer
                    .write_arena(trace)
                    .expect("trace writer failure");
            }
            Some(
                String::from_utf8(trace_writer.into_writer())
                    .expect("trace writer wrote invalid UTF-8"),
            )
        } else {
            None
        };

        Ok(CallRawResult {
            gas_used,
            block_number,
            success,
            trace,
            logs,
            exit_reason,
            return_data,
            formatted_trace,
        })
    }

    pub async fn set_block(&mut self, number: U256) -> Result<(), EvmError> {
        self.executor.env_mut().block.number = number;
        Ok(())
    }

    pub fn get_block(&self) -> U256 {
        self.executor.env().block.number
    }

    pub async fn set_block_timestamp(&mut self, timestamp: U256) -> Result<(), EvmError> {
        self.executor.env_mut().block.timestamp = timestamp;
        Ok(())
    }

    pub fn get_block_timestamp(&self) -> U256 {
        self.executor.env().block.timestamp
    }

    pub fn get_chain_id(&self) -> u64 {
        self.executor.env().cfg.chain_id
    }

    fn set_access_list(
        &mut self,
        access_list: Option<Vec<AccessListItem>>,
    ) -> Result<(), EvmError> {
        if let Some(access_list) = access_list {
            self.executor.env_mut().tx.access_list = access_list;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn test_evm_call_raw() {
        // Initialize a Tokio runtime for async test execution
        let mut rt = Runtime::new().unwrap();

        rt.block_on(async {
            // Initialize the EVM environment
            let mut evm = Evm::new(
                None,
                "https://eth-mainnet.g.alchemy.com/v2/alVqJQCHT4wtrXuZQehBZaxd9MiFYgGk".to_string(), // Fork URL
                Some(20534500), // Block number
                1_000_000,      // Gas limit
                Some("55UPD4PWFW6GNVHDAI54RGUD7D6NWEYMV9".to_string()),           // Etherscan key, if needed
            )
            .await;

            // Set up a transaction
            let request = CallRawRequest {
                from: "0xbC019B620b6A1d8AEDC3c89D300fbeC7169207Bf"
                    .parse()
                    .unwrap(),
                to: "0xdAC17F958D2ee523a2206206994597C13D831ec7"
                    .parse()
                    .unwrap(),
                value: None,
                data: Some(
                    "0xa9059cbb0000000000000000000000007e3c2ac421334fc96fdc7efb1b98498c5411904f000000000000000000000000000000000000000000000000000000044eaf9900"
                        .parse()
                        .unwrap(),
                ),
                access_list: None,
                format_trace: true, // Request trace formatting
            };

            // Execute the transaction and get the result
            let result = evm.call_raw(request).await.unwrap();

            // Output the result
            println!("Gas used: {}", result.gas_used);
            println!("Success: {}", result.success);
            println!("Logs: {:?}", result.logs);
            if let Some(trace) = result.formatted_trace {
                println!("Trace: {}", trace);
            }

            // Assert the results
            assert_eq!(result.success, false);
            assert!(result.gas_used > 0);
        });
    }
}
