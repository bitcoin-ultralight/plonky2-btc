use std::ops::AddAssign;
use std::ops::MulAssign;

use ::btc::btc::MultiHeaderTarget;
use anyhow::Result;
use btc::btc::make_multi_header_circuit;
use hex::decode;
use num::BigUint;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;
use plonky2_ecdsa::gadgets::biguint::CircuitBuilderBiguint;
use plonky2_field::extension::Extendable;
use plonky2_u32::gadgets::arithmetic_u32::CircuitBuilderU32;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

fn to_bits(msg: Vec<u8>) -> Vec<bool> {
    let mut res = Vec::new();
    for i in 0..msg.len() {
        let char = msg[i];
        for j in 0..8 {
            if (char & (1 << 7 - j)) != 0 {
                res.push(true);
            } else {
                res.push(false);
            }
        }
    }
    res
}

fn compute_exp_and_mantissa(header_bits: Vec<bool>) -> (u32, u64) {
    let mut d = 0;
    for i in 600..608 {
        d += ((header_bits[i]) as u32) << (608 - i - 1);
    }
    let exp = 8 * (d - 3);
    let mut mantissa = 0;
    for i in 576..584 {
        mantissa += ((header_bits[i]) as u64) << (584 - i - 1);
    }
    for i in 584..592 {
        mantissa += ((header_bits[i]) as u64) << (592 - i - 1 + 8);
    }
    for i in 592..600 {
        mantissa += ((header_bits[i]) as u64) << (600 - i - 1 + 16);
    }

    (exp, mantissa)
}

fn compute_work(exp: u32, mantissa: u64) -> BigUint {
    let mut my_threshold_bits = Vec::new();
    for i in 0..256 {
        if i < 256 - exp && mantissa & (1 << (255 - exp - i)) != 0 {
            my_threshold_bits.push(true);
        } else {
            my_threshold_bits.push(false);
        }
    }
    let mut acc: BigUint = BigUint::new(vec![1]);
    let mut denominator: BigUint = BigUint::new(vec![0]);
    for i in 0..256 {
        if my_threshold_bits[255 - i] {
            denominator.add_assign(acc.clone());
        }
        acc.mul_assign(BigUint::new(vec![2]));
    }
    let numerator = acc;
    let correct_work = numerator / denominator;
    return correct_work;
}

fn compile_l1_circuit() -> Result<(CircuitData<F, C, D>, MultiHeaderTarget)> {
    let num_headers = 10;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = make_multi_header_circuit(&mut builder, num_headers);

    let mut public_start_hash = Vec::new();
    for i in 0..256 {
        public_start_hash.push(builder.add_virtual_bool_target_unsafe());
        builder.register_public_input(public_start_hash[i].target);
        builder.connect(public_start_hash[i].target, targets.hashes[0][i].target);
    }

    let mut public_end_hash = Vec::new();
    for i in 0..256 {
        public_end_hash.push(builder.add_virtual_bool_target_unsafe());
        builder.register_public_input(public_end_hash[i].target);
        builder.connect(
            public_end_hash[i].target,
            targets.hashes[num_headers - 1][i].target,
        );
    }

    let public_total_work = builder.add_virtual_biguint_target(8);
    for i in 0..8 {
        builder.register_public_input(public_total_work.limbs[i].0);
        builder.connect(public_total_work.limbs[i].0, targets.total_work.limbs[i].0);
    }

    Ok((builder.build::<C>(), targets))
}

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

fn run_l1_circuit(
    data: CircuitData<F, C, D>,
    targets: MultiHeaderTarget,
    headers: [&str; 10],
    expected_hashes: [&str; 10],
) -> Result<ProofTuple<F, C, D>> {
    let num_headers = 10;
    let mut total_work = BigUint::new(vec![0]);
    let mut pw = PartialWitness::<F>::new();

    for h in 0..num_headers {
        let header_bits = to_bits(decode(headers[h]).unwrap());
        for i in 0..80 * 8 {
            pw.set_bool_target(targets.headers[h * 80 * 8 + i], header_bits[i]);
        }

        let (exp, mantissa) = compute_exp_and_mantissa(header_bits);
        let header_work = compute_work(exp, mantissa);
        total_work.add_assign(header_work);

        for i in 0..256 {
            if i < 256 - exp && mantissa & (1 << (255 - exp - i)) != 0 {
                pw.set_bool_target(targets.multi_threshold_bits[h * 256 + i as usize], true);
            } else {
                pw.set_bool_target(targets.multi_threshold_bits[h * 256 + i as usize], false);
            }
        }
    }

    let proof = data.prove(pw).unwrap();

    Ok((proof, data.verifier_only, data.common))
}

fn main() -> Result<()> {
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
    let (data, targets) = compile_l1_circuit()?;
    let elapsed = now.elapsed().as_millis();
    println!("circuit compilation took {}ms", elapsed);

    let now = std::time::Instant::now();
    let proof = run_l1_circuit(data, targets, headers, expected_hashes)?;
    let elapsed = now.elapsed().as_millis();
    println!("proof generationt took {}ms", elapsed);

    println!("public inputs {:?}", proof.0.public_inputs);
    Ok(())
}
