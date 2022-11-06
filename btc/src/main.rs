use btc::l1::{compile_l1_circuit, run_l1_circuit, compile_and_run_ln_circuit};
use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};

fn main() -> anyhow::Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let headers = [
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
        "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
        "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
        "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
        "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477",
        "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
        "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86",
        "010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666",
        "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53"
    ];
    let expected_hashes = [
        "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        "4860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000",
        "bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a00000000",
        "4944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b58200000000",
        "85144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000",
        "fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000",
        "8d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a0313000000000",
        "4494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000",
        "c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000",
        "0508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000",
    ];
    let now = std::time::Instant::now();
    let (data, targets) = compile_l1_circuit(2)?;
    let elapsed = now.elapsed().as_millis();
    println!("circuit compilation took {}ms", elapsed);

    // let now = std::time::Instant::now();
    // let proof = run_l1_circuit(data, targets, headers, expected_hashes)?;
    // let elapsed = now.elapsed().as_millis();
    // println!("proof generationt took {}ms", elapsed);
    // println!("public inputs {:?}", proof.0.public_inputs);

    let headers_1 = [
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299", 
    ];

    let headers_2 = [
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
        "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
    ];

    let headers_3 = [
        "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
        "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
    ];

    let headers_4 = [
        "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
        "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
    ];

    let proof1 = run_l1_circuit(&data, &targets, headers_1.as_slice(), 2)?;
    println!("stage 0, batch 1");

    let proof2 = run_l1_circuit(&data, &targets, headers_2.as_slice(), 2)?;
    println!("stage 0, batch 2");

    let proof3 = run_l1_circuit(&data, &targets, headers_3.as_slice(), 2)?;
    println!("stage 0, batch 3");

    let proof4 = run_l1_circuit(&data, &targets, headers_4.as_slice(), 2)?;
    println!("stage 0, batch 4");

    let proof_merge_1 = compile_and_run_ln_circuit(1, vec![proof1, proof2], &data.verifier_only, &data.common, 2)?;
    println!("stage 1, batch 0");

    let proof_merge_2 = compile_and_run_ln_circuit(1, vec![proof3, proof4], &data.verifier_only, &data.common, 2)?;
    println!("stage 1, batch 1");

    let final_proof = compile_and_run_ln_circuit(2, vec![proof_merge_1.0, proof_merge_2.0], &proof_merge_1.1, &proof_merge_1.2, 2)?;
    println!("stage 2, batch 0");

    Ok(())
}
