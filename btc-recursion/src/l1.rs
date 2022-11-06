use anyhow::Result;
use btc::btc::make_header_circuit;
use btc::btc::make_multi_header_circuit;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::{
    CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig};
use plonky2::recursion::cyclic_recursion::{
    check_cyclic_proof_verifier_data, set_cyclic_recursion_data_target, CyclicRecursionData,
    CyclicRecursionTarget,
};
use plonky2_field::types::Field;
use plonky2_u32::gadgets::arithmetic_u32::CircuitBuilderU32;

use crate::recursion;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

pub struct L1Circuit {
    circuit_data: CircuitData<F, C, D>,
    recursion_target: CyclicRecursionTarget<D>,
}

pub fn create_header_bits(builder: CircuitBuilder<F, D>, public: bool) -> Vec<BoolTarget> {
    let out = Vec::new();
    for i in 0..80 * 8 {
        out.push(builder.add_virtual_bool_target_unsafe());
        if public {
            builder.register_public_input(out[i])
        }
    }
    return out;
}

pub fn create_hash_bits(builder: CircuitBuilder<F, D>, public: bool) -> Vec<BoolTarget> {
    let out = Vec::new();
    for i in 0..256 {
        out.push(builder.add_virtual_bool_target_unsafe());
        if public {
            builder.register_public_input(out[i])
        }
    }
    return out;
}

impl L1Circuit {
    pub fn build() -> Result<L1Circuit> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        // base case
        let base_parent_hash = create_hash_bits(builder, true);
        let mut base_parent_total_work = builder.add_virtual_public_input();

        // inputs constrained by cyclic recursion
        let mut parent_hash = create_header_bits(builder, false);
        let parent_total_work = builder.add_virtual_target();

        // inputs from right now
        let mut input_parent_hash = create_hash_bits(builder, false);
        let mut input_parent_total_work = builder.add_virtual_target();
        let mut input_header_bits = create_header_bits(builder, false);
        let mut input_threshold_bits = create_header_bits(builder, false);

        // outputs
        let mut output_parent_hash = create_header_bits(builder, false);
        let output_total_work = builder.add_virtual_target();

        // public inputs from last proof
        let old_pis = [
            base_parent_hash.into_iter().map(|x| x.target).collect(),
            vec![base_total_work],
            parent_hash.into_iter().map(|x| x.target).collect(),
            vec![total_work],
        ]
        .concat();
        let mut common_data = recursion::common_data_for_recursion::<F, C, D>();
        let base_case = builder.add_virtual_bool_target_safe();
        let cyclic_data_target = builder
            .cyclic_recursion::<C>(base_case, &old_pis, &mut common_data)
            .unwrap();

        let mut input_parent_hash_bis = Vec::new();
        for i in 0..256 {
            input_parent_hash_bis.push(builder.add_virtual_bool_target_unsafe());
            input_parent_hash_bis[i] = BoolTarget::new_unsafe(builder.select(
                cyclic_data_target.base_case,
                base_parent_hash[i].target,
                parent_hash[i].target,
            ));
            builder.connect(input_parent_hash[i].target, input_parent_hash_bis[i].target);
        }

        let input_total_work_bis =
            builder.select(cyclic_data_target.base_case, base_total_work, total_work);
        builder.connect(input_total_work, input_total_work_bis);

        for i in 0..256 {
            builder.connect(targets.header_bits[i])
        }

        /* old code */

        // state transition
        let input_x = builder.add_virtual_target(); // either x or x_base
        let x = builder.add_virtual_target(); // constrained by cyclic_recursion

        let y = builder.add_const(input_x, GoldilocksField(7));
        builder.register_public_input(y);

        // block number
        let old_block_number = builder.add_virtual_target(); // constrainted by cyclic_recursion
        let block_number = builder.add_virtual_target(); // constrained later via connect
        builder.register_public_input(block_number);

        // cyclic recursion
        let old_pis = [x_base, x, old_block_number];
        let mut common_data = recursion::common_data_for_recursion::<F, C, D>();
        let base_case = builder.add_virtual_bool_target_safe();
        let cyclic_data_target = builder
            .cyclic_recursion::<C>(base_case, &old_pis, &mut common_data)
            .unwrap();

        let input_x_bis = builder.select(cyclic_data_target.base_case, x_base, x);
        builder.connect(input_x, input_x_bis);

        let one = builder.one();
        let block_number_bis = builder.add(old_block_number, one);
        builder.connect(block_number, block_number_bis);

        let cyclic_circuit_data = builder.build::<C>();
        let circuit = L1Circuit {
            circuit_data: cyclic_circuit_data,
            recursion_target: cyclic_data_target,
        };
        Ok(circuit)
    }

    pub fn generate_base_proof(
        &self,
        start_x: u64,
        start_block_number: u64,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        let public_inputs = [
            GoldilocksField(start_x),
            F::ZERO,
            GoldilocksField(start_block_number),
        ];
        let cyclic_recursion_data = CyclicRecursionData {
            proof: &None,
            verifier_data: &self.circuit_data.verifier_only,
            common_data: &self.circuit_data.common,
        };

        set_cyclic_recursion_data_target(
            &mut pw,
            &self.recursion_target,
            &cyclic_recursion_data,
            &public_inputs,
        )?;
        let proof = self.circuit_data.prove(pw)?;

        check_cyclic_proof_verifier_data(
            &proof,
            cyclic_recursion_data.verifier_data,
            cyclic_recursion_data.common_data,
        )?;
        self.circuit_data.verify(proof.clone())?;

        Ok(proof)
    }

    pub fn generate_next_proof(
        &self,
        prev_proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        let cyclic_recursion_data = CyclicRecursionData {
            proof: &Some(prev_proof.clone()),
            verifier_data: &self.circuit_data.verifier_only,
            common_data: &self.circuit_data.common,
        };
        set_cyclic_recursion_data_target(
            &mut pw,
            &self.recursion_target,
            &cyclic_recursion_data,
            &[],
        )?;
        let proof = self.circuit_data.prove(pw)?;
        check_cyclic_proof_verifier_data(
            &proof,
            cyclic_recursion_data.verifier_data,
            cyclic_recursion_data.common_data,
        )?;
        self.circuit_data.verify(proof.clone())?;
        Ok(proof)
    }

    pub fn generate_proof(
        &self,
        start_x: u64,
        start_block_number: u64,
        end_block_number: u64,
    ) -> Result<ProofTuple<F, C, D>> {
        let mut proof: ProofWithPublicInputs<F, C, D> =
            self.generate_base_proof(start_x, start_block_number)?;

        for current_block_number in start_block_number..end_block_number {
            let start = std::time::Instant::now();
            if current_block_number != start_block_number {
                proof = self.generate_next_proof(proof.clone())?;
            }
            println!(
                "current_block_number={}, ms={}, public_inputs[2]={}",
                current_block_number,
                start.elapsed().as_millis(),
                proof.clone().public_inputs.get(2).unwrap(),
            );

            self.circuit_data.verify(proof.clone())?;
        }

        Ok((
            proof,
            self.circuit_data.verifier_only.clone(),
            self.circuit_data.common.clone(),
        ))
    }
}
