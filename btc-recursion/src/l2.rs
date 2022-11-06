use anyhow::Result;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

pub struct L2Circuit {
    circuit_data: CircuitData<F, C, D>,
}

impl L2Circuit {
    pub fn build_and_generate_witness(
        proofs: Vec<ProofTuple<F, C, D>>,
    ) -> Result<(L2Circuit, PartialWitness<F>)> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let mut pw = PartialWitness::new();

        for proof in proofs {
            let (inner_proof, inner_vd, inner_cd) = proof;
            let pt = builder.add_virtual_proof_with_pis::<C>(&inner_cd);
            let inner_data = VerifierCircuitTarget {
                circuit_digest: builder.add_virtual_hash(),
                constants_sigmas_cap: builder
                    .add_virtual_cap(inner_cd.config.fri_config.cap_height),
            };
            pw.set_proof_with_pis_target(&pt, &inner_proof);
            pw.set_cap_target(
                &inner_data.constants_sigmas_cap,
                &inner_vd.constants_sigmas_cap,
            );
            pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);
            builder.verify_proof::<C>(pt, &inner_data, &inner_cd);
        }

        let circuit_data = builder.build::<C>();
        let circuit = L2Circuit { circuit_data };
        Ok((circuit, pw))
    }

    pub fn generate_proof(&self, pw: PartialWitness<F>) -> Result<ProofWithPublicInputs<F, C, D>> {
        let proof = self.circuit_data.prove(pw)?;
        self.circuit_data.verify(proof.clone())?;
        Ok(proof)
    }
}