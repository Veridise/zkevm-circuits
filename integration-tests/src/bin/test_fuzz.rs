use ethers::{
    abi::{self, Tokenize},
    contract::{builders::ContractCall, Contract, ContractFactory},
    core::types::{
        transaction::eip2718::TypedTransaction, Address, TransactionReceipt, TransactionRequest,
        U256, U64, Bytes
    },
    core::utils::WEI_IN_ETHER,
    middleware::SignerMiddleware,
    providers::{Middleware, PendingTransaction},
    signers::Signer,
};
use integration_tests::{
    get_client, get_provider, get_wallet
};
use bus_mapping::circuit_input_builder::BuilderClient;
use zkevm_circuits::evm_circuit::{test::run_test_circuit, witness::block_convert};

use std::fs;
use std::env;
use std::thread::sleep;
use std::time::Duration;

use protobuf;
use std::collections::{HashMap, HashSet};

mod fuzzer;


static GENESIS_ADDRESS: &str = "2adc25665018aa1fe0e6bc666dac8fc2697ff9ba";


pub fn convert_to_proto(fuzz_data: &[u8]) -> Option<fuzzer::Fuzzed> {
    match protobuf::parse_from_bytes::<fuzzer::Fuzzed>(fuzz_data) {
        Ok(fuzzed) => Some(fuzzed),
        Err(_) => None,
    }
}

async fn run_blocks(fuzzed: &fuzzer::Fuzzed) {
    // connect to geth
    let cli = get_client();
    let prov = get_provider();

    // Wait for geth to be online.
    loop {
        match prov.client_version().await {
            Ok(_version) => {
                break;
            }
            Err(_err) => {
                sleep(Duration::from_millis(500));
            }
        }
    }

    // Get addresses
    let coinbase = cli.get_coinbase().await.unwrap();
    
    // map genesis to coinbase
    let mut addresses = HashMap::new();
    addresses.insert(GENESIS_ADDRESS, coinbase);

    // vector to save addresses produced by fuzzer, we use it to find the
    // correct address
    let mut fuzzed_addresses = Vec::new();
    fuzzed_addresses.push(GENESIS_ADDRESS);

    // map fuzzing addresses to existing addresses
    for (i, builtin_addr) in fuzzed.get_builtin_addrs().iter().enumerate() {
        let wallet = get_wallet(i as u32);
        let address = wallet.address();
        addresses.insert(&builtin_addr, address);
        fuzzed_addresses.push(&builtin_addr);
    }

    let mut blocks_to_prove = HashSet::new();

    let mut blocks_sorted_by_number = fuzzed.get_blocks().to_vec();
    blocks_sorted_by_number.sort_by(|a, b| a.get_number().cmp(&b.get_number()));

    for block in blocks_sorted_by_number {
        // stop miner to add all transactions in a single block
        cli.miner_stop().await.expect("cannot stop miner");
        let mut pending_txs = Vec::new();
        let mut block_errors = Vec::new();
        let mut block_succeed = 0;

        for tx in block.get_transactions() {
            let from = addresses.get(tx.get_sender()).unwrap();
            let data;

            let mut tx_geth;

            // if we set gas and gas_price the transaction is not completed
            if tx.get_is_create_tx() {
                data = [tx.get_create_tx_constructor(),
                        tx.get_create_tx_constructor_postfix(),
                        tx.get_create_tx_contract(),
                        tx.get_create_tx_contract_postfix()].concat().to_vec();
                tx_geth = TransactionRequest::new()
                    .from(from.clone())
                    .value(tx.get_value());
            } else {
                let to = addresses
                    .get(fuzzed_addresses
                    .get(tx.get_receiver() as usize % fuzzed_addresses.len())
                    .unwrap()).unwrap();
                data = tx.get_call_tx_data().to_vec();
                tx_geth = TransactionRequest::new()
                    .from(from.clone())
                    .to(to.clone())
                    .value(tx.get_value());
            }

            if data.len() > 0 {
                tx_geth.data = Some(Bytes::from(data));
            }

            //println!("{:?}", tx_geth);

            // Submit the transaction and get any error
            let pending_tx = match prov.send_transaction(tx_geth, None).await {
                Ok(r) => Some(r),
                Err(err) => {
                    block_errors.push(format!("error: cannot send transaction: {:?}", err));
                    None
                }
            };
            if let Some(p) = pending_tx {
                pending_txs.push(p)
            }
        }

        // start miner
        cli.miner_start().await.expect("cannot start miner");
        for tx in pending_txs {
            match tx.await {
                Ok(_) => {
                    block_succeed = block_succeed + 1;
                    ()
                },
                Err(err) => {
                    block_errors.push(format!("error: cannot confirm tx: {:?}", err));
                    ()
                },
            };
        }
        println!("errors: {:?}", block_errors);
        println!("succeed: {}", block_succeed);

        let block_num = prov.get_block_number().await.expect("cannot get block_num");
        blocks_to_prove.insert(block_num);
    }

    println!("{:?}", blocks_to_prove);

    for block_num in blocks_to_prove {
        let block_cli = get_client();
        let builder_cli = BuilderClient::new(block_cli).await.unwrap();
        let (builder, _) = builder_cli.gen_inputs(block_num.as_u64()).await.unwrap();
        let block = block_convert(&builder.block, &builder.code_db);
        run_test_circuit(block).expect("evm_circuit verification failed");
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let data = fs::read(args[1].clone()).expect("Unable to read file");
    match convert_to_proto(&data) {
        Some(proto) => {
            run_blocks(&proto).await;
        },
        None => (),
    }
}
