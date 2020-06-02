use rand;

#[macro_use]
extern crate criterion;

use algebra::fields::PrimeField;
use algebra::One;
use algebra::{mnt4_298::{MNT4_298, Fr as MNT4Fr}, mnt6_298::{MNT6_298, Fr as MNT6Fr}};
use criterion::Criterion;
use marlin::{Marlin, IndexProverKey, UniversalSRS};
use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use blake2::Blake2s;
use poly_commit::marlin_kzg10::MarlinKZG10;
use algebra_core::UniformRand;

type MultiPcMnt4 = MarlinKZG10<MNT4_298>;
type MultiPcMnt6 = MarlinKZG10<MNT6_298>;
type MarlinInstMnt4 = Marlin<MNT4Fr, MultiPcMnt4, Blake2s>;
type MarlinInstMnt6 = Marlin<MNT6Fr, MultiPcMnt6, Blake2s>;

struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let a = cs.alloc(|| "a", || self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.alloc(|| "b", || self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.alloc_input(
            || "c",
            || {
                let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                a.mul_assign(&b);
                Ok(a)
            },
        )?;

        for i in 0..(self.num_variables - 3) {
            let _ = cs.alloc(
                || format!("var {}", i),
                || self.a.ok_or(SynthesisError::AssignmentMissing),
            )?;
        }

        for i in 0..self.num_constraints - 1{
            cs.enforce(
                || format!("constraint {}", i),
                |lc| lc + a,
                |lc| lc + b,
                |lc| lc + c,
            );
        }

        cs.enforce(
            || "constraint {}",
            |lc| lc,
            |lc| lc,
            |lc| lc,
        );

        Ok(())
    }
}

fn index_mnt4<'a>(num_constraints: usize) -> UniversalSRS<MNT4Fr, MultiPcMnt4> {
    let rng = &mut rand::thread_rng();
    let srs = MarlinInstMnt4::universal_setup(num_constraints, 10, num_constraints , rng).unwrap();
    srs
}

fn index_mnt6<'a>(num_constraints: usize) -> UniversalSRS<MNT6Fr, MultiPcMnt6> {
    let rng = &mut rand::thread_rng();
    let srs = MarlinInstMnt6::universal_setup(num_constraints , 10, num_constraints, rng).unwrap();
    srs
}

fn prepare_mnt4<'a>(num_constraints: usize, srs: &'a UniversalSRS<MNT4Fr, MultiPcMnt4>) -> IndexProverKey<'a, MNT4Fr, MultiPcMnt4, DummyCircuit<MNT4Fr>> {
    let rng = &mut rand::thread_rng();
    let c = DummyCircuit::<MNT4Fr> { a:Some(MNT4Fr::rand(rng)), b:Some(MNT4Fr::rand(rng)), num_variables: 10, num_constraints: num_constraints };

    let (pk, _) = MarlinInstMnt4::index(&srs, c).unwrap();

    pk
}

fn prepare_mnt6<'a>(num_constraints: usize, srs: &'a UniversalSRS<MNT6Fr, MultiPcMnt6>) -> IndexProverKey<'a, MNT6Fr, MultiPcMnt6, DummyCircuit<MNT6Fr>> {
    let rng = &mut rand::thread_rng();
    let c = DummyCircuit::<MNT6Fr> { a:Some(MNT6Fr::rand(rng)), b:Some(MNT6Fr::rand(rng)), num_variables: 10, num_constraints: num_constraints };

    let (pk, _) = MarlinInstMnt6::index(&srs, c).unwrap();

    pk
}

fn bench_prove_mnt4<'a>(num_constraints: usize, ipk: &IndexProverKey<'a, MNT4Fr, MultiPcMnt4, DummyCircuit<MNT4Fr>>) {
    let rng = &mut rand::thread_rng();
    let c = DummyCircuit::<MNT4Fr> { a: Some(MNT4Fr::rand(rng)), b:Some(MNT4Fr::rand(rng)), num_variables: 10, num_constraints: num_constraints };

    let _ = MarlinInstMnt4::prove(ipk, c, rng).unwrap();
}

fn bench_prove_mnt6<'a>(num_constraints: usize, ipk: &IndexProverKey<'a, MNT6Fr, MultiPcMnt6, DummyCircuit<MNT6Fr>>) {
    let rng = &mut rand::thread_rng();
    let c = DummyCircuit::<MNT6Fr> { a: Some(MNT6Fr::rand(rng)), b:Some(MNT6Fr::rand(rng)),  num_variables: 10, num_constraints: num_constraints };

    let _ = MarlinInstMnt6::prove(ipk, c, rng).unwrap();
}

fn bench_prove_mnt4_2_10_to_2_20(c: &mut Criterion) {
    for i in [
        1024usize,
        2048usize,
        4096usize,
        8192usize,
        16384usize,
        32768usize,
        65536usize,
        131072usize,
        262144usize,
        524288usize,
        1048576usize,
    ]
    .iter()
    {
        let srs = index_mnt4(i.clone());
        let params = prepare_mnt4(i.clone(), &srs);
        c.bench_function(&format!("{}", i), |b| {
            b.iter(|| bench_prove_mnt4(i.clone(), &params.clone()))
        });
    }
}

fn bench_prove_mnt6_2_10_to_2_20(c: &mut Criterion) {
    for i in [
        1024usize,
        2048usize,
        4096usize,
        8192usize,
        16384usize,
        32768usize,
        65536usize,
        131072usize,
        262144usize,
        524288usize,
        1048576usize,
    ]
    .iter()
    {
        let srs = index_mnt6(i.clone());
        let params = prepare_mnt6(i.clone(), &srs);
        c.bench_function(&format!("{}", i), |b| {
            b.iter(|| bench_prove_mnt6(i.clone(), &params.clone()))
        });
    }
}

criterion_group! {
    name = mnt4;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_mnt4_2_10_to_2_20
}

criterion_group! {
    name = mnt6;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_mnt6_2_10_to_2_20
}

criterion_main!(mnt4, mnt6);
