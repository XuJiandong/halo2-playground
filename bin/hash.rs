use ff::Field;
use halo2_playground::GOD_PRIVATE_KEY;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        group::ff,
        FieldExt,
    },
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Instance,
    },
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};

use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength, Spec},
    Hash, Pow5Chip, Pow5Config,
};
use rand_xorshift::XorShiftRng;
use std::convert::TryInto;
use std::marker::PhantomData;

use rand::{RngCore, SeedableRng};

#[derive(Clone, Copy)]
struct HashCircuit<S, const WIDTH: usize, const RATE: usize, const L: usize>
where
    S: Spec<Fr, WIDTH, RATE> + Clone + Copy,
{
    message: Value<[Fr; L]>,
    _spec: PhantomData<S>,
}

#[derive(Debug, Clone)]
struct MyConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    input: [Column<Advice>; L],
    expected: Column<Instance>,
    poseidon_config: Pow5Config<Fr, WIDTH, RATE>,
}

impl<S, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fr>
    for HashCircuit<S, WIDTH, RATE, L>
where
    S: Spec<Fr, WIDTH, RATE> + Copy + Clone,
{
    type Config = MyConfig<WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let expected = meta.instance_column();
        meta.enable_equality(expected);
        let partial_sbox = meta.advice_column();

        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        meta.enable_constant(rc_b[0]);

        Self::Config {
            input: state[..RATE].try_into().unwrap(),
            expected,
            poseidon_config: Pow5Chip::configure::<S>(
                meta,
                state.try_into().unwrap(),
                partial_sbox,
                rc_a.try_into().unwrap(),
                rc_b.try_into().unwrap(),
            ),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.poseidon_config.clone());

        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                let message_word = |i: usize| {
                    let value = self.message.map(|message_vals| message_vals[i]);
                    region.assign_advice(
                        || format!("load message_{}", i),
                        config.input[i],
                        0,
                        || value,
                    )
                };

                let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                Ok(message?.try_into().unwrap())
            },
        )?;

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        layouter.constrain_instance(output.cell(), config.expected, 0)
    }
}

#[derive(Debug, Clone, Copy)]
struct MySpec<const WIDTH: usize, const RATE: usize>;

impl<const WIDTH: usize, const RATE: usize> Spec<Fr, WIDTH, RATE> for MySpec<WIDTH, RATE> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fr) -> Fr {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        0
    }
}

const K: u32 = 7;

fn run_poseidon<S, const WIDTH: usize, const RATE: usize, const L: usize>()
where
    S: Spec<Fr, WIDTH, RATE> + Copy + Clone,
{
    println!("WIDTH = {}, RATE = {}, L = {}", WIDTH, RATE, L);

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let message: [Fr; L] = (0..L)
        .map(|_| Fr::from_u128(rng.next_u32() as u8 as u128))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let output = poseidon::Hash::<_, S, ConstantLength<L>, WIDTH, RATE>::init().hash(message);

    let circuit = HashCircuit::<S, WIDTH, RATE, L> {
        message: Value::known(message),
        _spec: PhantomData,
    };

    let s = Fr::from_u128(GOD_PRIVATE_KEY);
    let general_params = ParamsKZG::<Bn256>::unsafe_setup_with_s(K, s);
    let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();

    let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk");
    let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk");
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    let rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        XorShiftRng,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        HashCircuit<S, WIDTH, RATE, L>,
    >(
        &general_params,
        &pk,
        &[circuit],
        &[&[&[output]]],
        rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    //
    let mut verifier_params_buf = vec![];
    verifier_params
        .write(&mut verifier_params_buf)
        .expect("write");
    let mut vk_buf = vec![];
    pk.get_vk().write(&mut vk_buf).expect("write");
    println!("proof length : {}", proof.len());
    println!("verifier parameters length : {}", verifier_params_buf.len());
    println!("vk length: {}", vk_buf.len());

    let strategy = SingleStrategy::new(&general_params);
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        &verifier_params,
        pk.get_vk(),
        strategy,
        &[&[&[output]]],
        &mut transcript,
    )
    .expect("verify_proof");
}

fn main() {
    run_poseidon::<MySpec<3, 2>, 3, 2, 2>();
}
