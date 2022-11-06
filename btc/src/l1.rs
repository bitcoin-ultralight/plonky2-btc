#![feature(generic_const_exprs)]
use std::ops::AddAssign;
use std::ops::MulAssign;

use anyhow::Result;
use hex::decode;
use num::BigUint;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2_ecdsa::gadgets::biguint::CircuitBuilderBiguint;
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;

use crate::btc::make_multi_header_circuit;
use crate::btc::MultiHeaderTarget;

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

// const FACTORS: [usize; 6] = [12, 12, 9, 9, 9, 7];
//const FACTORS: [usize; 3] = [2, 2, 2];

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

pub fn compile_l1_circuit(num_headers: usize) -> Result<(CircuitData<F, C, D>, MultiHeaderTarget)> {
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

pub fn run_l1_circuit(
    data: &CircuitData<F, C, D>,
    targets: &MultiHeaderTarget,
    headers: &[&str],
    num_headers: usize,
) -> Result<ProofWithPublicInputs<F, C, D>> {
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
    // data.verify(proof.clone())?;

    Ok(proof)
}

pub fn compile_and_run_ln_circuit(
    layer_idx: usize,
    inner_proofs: Vec<ProofWithPublicInputs<F, C, 2>>,
    inner_vd: &VerifierOnlyCircuitData<C, D>,
    inner_cd: &CommonCircuitData<F, D>,
    num_proofs: usize,
    only_compile: bool,
) -> Result<(
    Option<ProofWithPublicInputs<F, C, D>>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
)> {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let mut pw = PartialWitness::<F>::new();

    let mut public_start_hash = Vec::new();
    for i in 0..256 {
        public_start_hash.push(builder.add_virtual_bool_target_unsafe());
        builder.register_public_input(public_start_hash[i].target);
    }

    let mut public_end_hash = Vec::new();
    for i in 0..256 {
        public_end_hash.push(builder.add_virtual_bool_target_unsafe());
        builder.register_public_input(public_end_hash[i].target);
    }

    let public_total_work = builder.add_virtual_biguint_target(8);
    for i in 0..8 {
        builder.register_public_input(public_total_work.limbs[i].0);
    }

    let mut pts = Vec::new();
    let mut inner_datas = Vec::new();

    let zero = builder.zero();
    let mut work_accumulator = builder.add_virtual_biguint_target(8);
    for i in 0..8 {
        builder.connect(work_accumulator.limbs[i].0, zero);
    }

    for i in 0..num_proofs {
        let pt: ProofWithPublicInputsTarget<D> = builder.add_virtual_proof_with_pis::<C>(inner_cd);
        let inner_data = VerifierCircuitTarget {
            circuit_digest: builder.add_virtual_hash(),
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
        };
        if !only_compile {
            // We only set the witness if are not only compiling
            pw.set_proof_with_pis_target(&pt, &inner_proofs[i]);
            pw.set_verifier_data_target(&inner_data, inner_vd);
        }

        let current_work = builder.add_virtual_biguint_target(8);
        for i in 0..8 {
            builder.connect(pt.public_inputs[512 + i], current_work.limbs[i].0);
        }

        work_accumulator = builder.add_biguint(&work_accumulator, &current_work);

        if i == 0 {
            for i in 0..256 {
                builder.connect(public_start_hash[i].target, pt.public_inputs[i]);
            }
        }
        if i == num_proofs - 1 {
            for i in 0..256 {
                builder.connect(public_end_hash[i].target, pt.public_inputs[256 + i]);
            }
            for i in 0..8 {
                builder.connect(work_accumulator.limbs[i].0, public_total_work.limbs[i].0);
            }
        }

        pts.push(pt);
        inner_datas.push(inner_data);
    }

    for i in 0..(num_proofs - 1) {
        let pt1: &ProofWithPublicInputsTarget<D> = &pts[i];
        let pt2: &ProofWithPublicInputsTarget<D> = &pts[i + 1];
        for i in 0..256 {
            builder.connect(pt1.public_inputs[256 + i], pt2.public_inputs[i]);
        }
    }

    pts.into_iter().enumerate().for_each(|(i, pt)| {
        builder.verify_proof::<C>(pt, &inner_datas[i], inner_cd);
    });

    let data = builder.build::<C>();
    if !only_compile {
        let proof = data.prove(pw).unwrap();
        data.verify(proof.clone())?;
        // data.verify(proof.clone())?;
        Ok((Some(proof), data.verifier_only, data.common))
    } else {
        Ok((None, data.verifier_only, data.common))
    }
}
