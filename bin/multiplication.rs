use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::pasta::Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

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
            || "name",
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

fn main() {
    let dummy = Fp::from(0);

    let k = 4;

    let a = Fp::from(3);
    let b = Fp::from(5);
    let c = a * b;

    let circuit = DefaultCircuit {
        a: Value::known(a),
        b: Value::known(b),
    };
    let public_inputs = vec![dummy, c];

    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
