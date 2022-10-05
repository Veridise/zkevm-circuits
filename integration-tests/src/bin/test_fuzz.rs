use bus_mapping::circuit_input_builder::BuilderClient;
use bus_mapping::operation::OperationContainer;
use eth_types::geth_types;
use halo2_proofs::{
    arithmetic::{CurveAffine, Field, FieldExt},
    dev::MockProver,
    halo2curves::{
        bn256::Fr,
        group::{Curve, Group},
    },
};
use integration_tests::{get_client, log_init, GenDataOutput, CHAIN_ID};
use lazy_static::lazy_static;
use log::trace;
use paste::paste;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::marker::PhantomData;
use zkevm_circuits::bytecode_circuit::dev::test_bytecode_circuit;
use zkevm_circuits::copy_circuit::dev::test_copy_circuit;
use zkevm_circuits::evm_circuit::witness::RwMap;
use zkevm_circuits::evm_circuit::{test::run_test_circuit, witness::block_convert};
use zkevm_circuits::state_circuit::StateCircuit;
use zkevm_circuits::tx_circuit::{
    sign_verify::SignVerifyChip, Secp256k1Affine, TxCircuit, POW_RAND_SIZE, VERIF_HEIGHT,
};
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
    get_provider, get_wallet
};

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
        // Test EVM circuit block
        let block_cli = get_client();
        let builder_cli = BuilderClient::new(block_cli).await.unwrap();
        let (builder, _) = builder_cli.gen_inputs(block_num.as_u64()).await.unwrap();
        let block = block_convert(&builder.block, &builder.code_db);
        run_test_circuit(block).expect("evm_circuit verification failed");

        // Test State circuit block
        // TODO maybe we can reuse the builder
        let cli = get_client();
        let cli = BuilderClient::new(cli).await.unwrap();
        let (builder, _) = cli.gen_inputs(block_num.as_u64()).await.unwrap();

        // Generate state proof
        let stack_ops = builder.block.container.sorted_stack();
        let memory_ops = builder.block.container.sorted_memory();
        let storage_ops = builder.block.container.sorted_storage();

        const STATE_DEGREE: usize = 17;

        let rw_map = RwMap::from(&OperationContainer {
            memory: memory_ops,
            stack: stack_ops,
            storage: storage_ops,
            ..Default::default()
        });

        let randomness = Fr::from(0xcafeu64);
        let circuit = StateCircuit::<Fr>::new(randomness, rw_map, 1 << 16);
        let power_of_randomness = circuit.instance();

        let prover = MockProver::<Fr>::run(STATE_DEGREE as u32, &circuit, power_of_randomness).unwrap();
        prover.verify().expect("state_circuit verification failed");
        
        // Test tx circuit
        const TX_DEGREE: u32 = 20;

        let cli = get_client();
        let cli = BuilderClient::new(cli).await.unwrap();

        let (_, eth_block) = cli.gen_inputs(block_num.as_u64()).await.unwrap();
        let txs: Vec<_> = eth_block
            .transactions
            .iter()
            .map(geth_types::Transaction::from)
            .collect();

        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();

        let randomness = Fr::random(&mut rng);
        let mut instance: Vec<Vec<Fr>> = (1..POW_RAND_SIZE + 1)
            .map(|exp| vec![randomness.pow(&[exp as u64, 0, 0, 0]); txs.len() * VERIF_HEIGHT])
            .collect();

        instance.push(vec![]);
        let circuit = TxCircuit::<Fr, 4, { 4 * (4 + 32 + 32) }> {
            sign_verify: SignVerifyChip {
                aux_generator,
                window_size: 2,
                _marker: PhantomData,
            },
            randomness,
            txs,
            chain_id: CHAIN_ID,
        };

        let prover = MockProver::run(TX_DEGREE, &circuit, instance).unwrap();

        prover.verify().expect("tx_circuit verification failed");

        // Test Bytecode circuit
        const BYTECODE_DEGREE: u32 = 16;

        let cli = get_client();
        let cli = BuilderClient::new(cli).await.unwrap();
        let (builder, _) = cli.gen_inputs(block_num.as_u64()).await.unwrap();
        let bytecodes: Vec<Vec<u8>> = builder.code_db.0.values().cloned().collect();

        test_bytecode_circuit::<Fr>(BYTECODE_DEGREE, bytecodes);

        // Test Copy circuit
        const COPY_DEGREE: u32 = 16;

        log::info!("test copy circuit, block number: {}", block_num);
        let cli = get_client();
        let cli = BuilderClient::new(cli).await.unwrap();
        let (builder, _) = cli.gen_inputs(block_num.as_u64()).await.unwrap();
        let block = block_convert(&builder.block, &builder.code_db);

        assert!(test_copy_circuit(COPY_DEGREE, block).is_ok());
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
