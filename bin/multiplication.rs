use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Instance, Selector,
    },
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        Rotation,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};

use rand::SeedableRng;
use rand_xorshift::XorShiftRng;

#[derive(Clone, Debug)]
struct Config {
    pub advice: [Column<Advice>; 2],
    pub instance: Column<Instance>,
    pub s_mul: Selector,
}

#[derive(Default)]
struct DefaultCircuit<F: FieldExt> {
    pub a: Value<F>,
    pub b: Value<F>,
}

impl<F: FieldExt> Circuit<F> for DefaultCircuit<F> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        let s_mul = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);
        meta.enable_equality(instance);

        meta.create_gate("mul", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_mul = meta.query_selector(s_mul);
            vec![s_mul * (lhs * rhs - out)]
        });

        Config {
            advice,
            instance,
            s_mul,
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let a = layouter.assign_region(
            || "load private a",
            |mut region| region.assign_advice(|| "private input", config.advice[0], 0, || self.a),
        )?;
        let b = layouter.assign_region(
            || "load private b",
            |mut region| region.assign_advice(|| "private input", config.advice[1], 0, || self.b),
        )?;
        let c = layouter.assign_region(
            || "a * b",
            |mut region: Region<'_, F>| {
                config.s_mul.enable(&mut region, 0)?;
                a.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;
                let value = a.value().copied() * b.value();
                region.assign_advice(|| "lhs * rhs", config.advice[0], 1, || value)
            },
        )?;
        layouter.constrain_instance(c.cell(), config.instance, 1)?;
        Ok(())
    }
}

#[cfg(feature = "dev-graph")]
fn render<F: FieldExt>(circuit: &impl Circuit<F>) {
    use plotters::prelude::*;
    let root = SVGBackend::new("multiplication.svg", (1024, 768)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Example Circuit Layout", ("sans-serif", 20))
        .unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .show_labels(true)
        .mark_equality_cells(true)
        .show_equality_constraints(true)
        .render(4, circuit, &root)
        .unwrap();
}

#[cfg(not(feature = "dev-graph"))]
fn render<F: FieldExt>(_: &impl Circuit<F>) {}

fn prove_and_verify(circuit: DefaultCircuit<Fr>, public_inputs: &[&[Fr]]) {
    let k = 4;
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let general_params = ParamsKZG::<Bn256>::setup(k, &mut rng);
    let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();

    let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk");
    let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk");

    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        XorShiftRng,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        DefaultCircuit<Fr>,
    >(
        &general_params,
        &pk,
        &[circuit],
        &[public_inputs],
        rng,
        &mut transcript,
    )
    .expect("create_proof");
    let proof = transcript.finalize();

    // verifier
    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleStrategy::new(&general_params);
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
        &[public_inputs],
        &mut verifier_transcript,
    )
    .expect("verify_proof");
}

fn main() {
    let dummy = Fr::from(0);

    let k = 4;

    let a = Fr::from(3);
    let b = Fr::from(5);
    let c = a * b;

    let circuit = DefaultCircuit {
        a: Value::known(a),
        b: Value::known(b),
    };
    let public_inputs = vec![dummy, c];
    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
    render(&circuit);

    prove_and_verify(circuit, &[&[dummy, c]]);
}
