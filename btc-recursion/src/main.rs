#![feature(generic_const_exprs)]
use anyhow::Result;

mod l1;
mod recursion;
mod l2;
use l1::L1Circuit;
use l2::L2Circuit;

fn main() -> Result<()> {
    let l1 = L1Circuit::build()?;
    let proof1 = l1.generate_proof(0, 0, 10)?;
    let proof2 = l1.generate_proof(10, 10, 20)?;

    let (l2, pw) = L2Circuit::build_and_generate_witness(vec![proof1, proof2])?;
    l2.generate_proof(pw)?;

    Ok(())
}