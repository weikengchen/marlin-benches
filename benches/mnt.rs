use rand;

#[macro_use]
extern crate criterion;

use algebra::fields::PrimeField;
use algebra::{
    bls12_381::{Bls12_381, Fr as BlsFr},
    mnt4_298::{Fr as MNT4Fr, MNT4_298},
    mnt4_753::{Fr as MNT4BigFr, MNT4_753},
    mnt6_298::{Fr as MNT6Fr, MNT6_298},
    mnt6_753::{Fr as MNT6BigFr, MNT6_753},
};
use algebra_core::UniformRand;
use blake2::Blake2s;
use criterion::Criterion;
use marlin::Marlin;
use poly_commit::marlin_pc::MarlinKZG10;
use r1cs_core::{lc, ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use std::ops::Mul;

type MultiPcMnt4 = MarlinKZG10<MNT4_298>;
type MultiPcMnt6 = MarlinKZG10<MNT6_298>;
type MultiPcBls = MarlinKZG10<Bls12_381>;
type MultiPcMnt4Big = MarlinKZG10<MNT4_753>;
type MultiPcMnt6Big = MarlinKZG10<MNT6_753>;

type MarlinInstMnt4 = Marlin<MNT4Fr, MultiPcMnt4, Blake2s>;
type MarlinInstMnt6 = Marlin<MNT6Fr, MultiPcMnt6, Blake2s>;
type MarlinInstBls = Marlin<BlsFr, MultiPcBls, Blake2s>;
type MarlinInstMnt4Big = Marlin<MNT4BigFr, MultiPcMnt4Big, Blake2s>;
type MarlinInstMnt6Big = Marlin<MNT6BigFr, MultiPcMnt6Big, Blake2s>;

struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> Clone for DummyCircuit<F> {
    fn clone(&self) -> Self {
        DummyCircuit {
            a: self.a.clone(),
            b: self.b.clone(),
            num_variables: self.num_variables.clone(),
            num_constraints: self.num_constraints.clone(),
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}

fn bench_prove(cr: &mut Criterion) {
    {
        let rng = &mut rand::thread_rng();
        let c = DummyCircuit::<BlsFr> {
            a: Some(BlsFr::rand(rng)),
            b: Some(BlsFr::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let srs = MarlinInstBls::universal_setup(65536, 10 + 1, 65536, rng).unwrap();
        let (pk, _) = MarlinInstBls::index(&srs, c.clone()).unwrap();

        cr.bench_function(&"bls", |b| {
            b.iter(|| MarlinInstBls::prove(&pk, c.clone(), rng).unwrap())
        });
    }
    {
        let rng = &mut rand::thread_rng();
        let c = DummyCircuit::<MNT4Fr> {
            a: Some(MNT4Fr::rand(rng)),
            b: Some(MNT4Fr::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let srs = MarlinInstMnt4::universal_setup(65536, 10 + 1, 65536, rng).unwrap();
        let (pk, _) = MarlinInstMnt4::index(&srs, c.clone()).unwrap();

        cr.bench_function(&"mnt4", |b| {
            b.iter(|| MarlinInstMnt4::prove(&pk, c.clone(), rng).unwrap())
        });
    }
    {
        let rng = &mut rand::thread_rng();
        let c = DummyCircuit::<MNT6Fr> {
            a: Some(MNT6Fr::rand(rng)),
            b: Some(MNT6Fr::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let srs = MarlinInstMnt6::universal_setup(65536, 10 + 1, 65536, rng).unwrap();
        let (pk, _) = MarlinInstMnt6::index(&srs, c.clone()).unwrap();

        cr.bench_function(&"mnt6", |b| {
            b.iter(|| MarlinInstMnt6::prove(&pk, c.clone(), rng).unwrap())
        });
    }
    {
        let rng = &mut rand::thread_rng();
        let c = DummyCircuit::<MNT4BigFr> {
            a: Some(MNT4BigFr::rand(rng)),
            b: Some(MNT4BigFr::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let srs = MarlinInstMnt4Big::universal_setup(65536, 10 + 1, 65536, rng).unwrap();
        let (pk, _) = MarlinInstMnt4Big::index(&srs, c.clone()).unwrap();

        cr.bench_function(&"mnt4Big", |b| {
            b.iter(|| MarlinInstMnt4Big::prove(&pk, c.clone(), rng).unwrap())
        });
    }
    {
        let rng = &mut rand::thread_rng();
        let c = DummyCircuit::<MNT6BigFr> {
            a: Some(MNT6BigFr::rand(rng)),
            b: Some(MNT6BigFr::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let srs = MarlinInstMnt6Big::universal_setup(65536, 10 + 1, 65536, rng).unwrap();
        let (pk, _) = MarlinInstMnt6Big::index(&srs, c.clone()).unwrap();

        cr.bench_function(&"mnt6Big", |b| {
            b.iter(|| MarlinInstMnt6Big::prove(&pk, c.clone(), rng).unwrap())
        });
    }
}

fn bench_verify(cr: &mut Criterion) {
    {
        let rng = &mut rand::thread_rng();
        let c = DummyCircuit::<BlsFr> {
            a: Some(BlsFr::rand(rng)),
            b: Some(BlsFr::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let srs = MarlinInstBls::universal_setup(65536, 10 + 1, 65536, rng).unwrap();
        let (pk, vk) = MarlinInstBls::index(&srs, c.clone()).unwrap();
        let proof = MarlinInstBls::prove(&pk, c.clone(), rng).unwrap();

        let c = c.a.unwrap().mul(c.b.unwrap());

        cr.bench_function(&"bls", |b| {
            b.iter(|| MarlinInstBls::verify(&vk, &vec![c], &proof, rng).unwrap())
        });
    }
    {
        let rng = &mut rand::thread_rng();
        let c = DummyCircuit::<MNT4Fr> {
            a: Some(MNT4Fr::rand(rng)),
            b: Some(MNT4Fr::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let srs = MarlinInstMnt4::universal_setup(65536, 10 + 1, 65536, rng).unwrap();
        let (pk, vk) = MarlinInstMnt4::index(&srs, c.clone()).unwrap();
        let proof = MarlinInstMnt4::prove(&pk, c.clone(), rng).unwrap();

        let c = c.a.unwrap().mul(c.b.unwrap());

        cr.bench_function(&"mnt4", |b| {
            b.iter(|| MarlinInstMnt4::verify(&vk, &vec![c], &proof, rng).unwrap())
        });
    }
    {
        let rng = &mut rand::thread_rng();
        let c = DummyCircuit::<MNT6Fr> {
            a: Some(MNT6Fr::rand(rng)),
            b: Some(MNT6Fr::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let srs = MarlinInstMnt6::universal_setup(65536, 10 + 1, 65536, rng).unwrap();
        let (pk, vk) = MarlinInstMnt6::index(&srs, c.clone()).unwrap();
        let proof = MarlinInstMnt6::prove(&pk, c.clone(), rng).unwrap();

        let c = c.a.unwrap().mul(c.b.unwrap());

        cr.bench_function(&"mnt6", |b| {
            b.iter(|| MarlinInstMnt6::verify(&vk, &vec![c], &proof, rng).unwrap())
        });
    }
    {
        let rng = &mut rand::thread_rng();
        let c = DummyCircuit::<MNT4BigFr> {
            a: Some(MNT4BigFr::rand(rng)),
            b: Some(MNT4BigFr::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let srs = MarlinInstMnt4Big::universal_setup(65536, 10 + 1, 65536, rng).unwrap();
        let (pk, vk) = MarlinInstMnt4Big::index(&srs, c.clone()).unwrap();
        let proof = MarlinInstMnt4Big::prove(&pk, c.clone(), rng).unwrap();

        let c = c.a.unwrap().mul(c.b.unwrap());

        cr.bench_function(&"mnt4Big", |b| {
            b.iter(|| MarlinInstMnt4Big::verify(&vk, &vec![c], &proof, rng).unwrap())
        });
    }
    {
        let rng = &mut rand::thread_rng();
        let c = DummyCircuit::<MNT6BigFr> {
            a: Some(MNT6BigFr::rand(rng)),
            b: Some(MNT6BigFr::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let srs = MarlinInstMnt6Big::universal_setup(65536, 10 + 1, 65536, rng).unwrap();
        let (pk, vk) = MarlinInstMnt6Big::index(&srs, c.clone()).unwrap();
        let proof = MarlinInstMnt6Big::prove(&pk, c.clone(), rng).unwrap();

        let c = c.a.unwrap().mul(c.b.unwrap());

        cr.bench_function(&"mnt6Big", |b| {
            b.iter(|| MarlinInstMnt6Big::verify(&vk, &vec![c], &proof, rng).unwrap())
        });
    }
}

criterion_group! {
    name = marlin_prove;
    config = Criterion::default().sample_size(10);
    targets = bench_prove
}

criterion_group! {
    name = marlin_verify;
    config = Criterion::default().sample_size(10);
    targets = bench_verify
}

criterion_main!(marlin_verify);
