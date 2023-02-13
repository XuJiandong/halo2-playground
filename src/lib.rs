use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::group::Curve;
use halo2_proofs::{
    plonk::{Error, VerifyingKey},
    poly::commitment::{Blind, CommitmentScheme, Params, Verifier},
};

pub const GOD_PRIVATE_KEY: u128 = 42;

pub fn commit_instances<'params, Scheme: CommitmentScheme, V: Verifier<'params, Scheme>>(
    params: &'params Scheme::ParamsVerifier,
    vk: &VerifyingKey<Scheme::Curve>,
    instances: &[&[&[Scheme::Scalar]]],
) -> Result<Vec<Vec<<Scheme as CommitmentScheme>::Curve>>, Error> {
    // Check that instances matches the expected number of instance columns
    for instances in instances.iter() {
        if instances.len() != vk.cs.num_instance_columns {
            return Err(Error::InvalidInstances);
        }
    }

    let instance_commitments = instances
        .iter()
        .map(|instance| {
            instance
                .iter()
                .map(|instance| {
                    if instance.len() > params.n() as usize - (vk.cs.blinding_factors() + 1) {
                        return Err(Error::InstanceTooLarge);
                    }
                    let mut poly = instance.to_vec();
                    poly.resize(params.n() as usize, Scheme::Scalar::zero());
                    let poly = vk.domain.lagrange_from_vec(poly);

                    Ok(params.commit_lagrange(&poly, Blind::default()).to_affine())
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(instance_commitments)
}
