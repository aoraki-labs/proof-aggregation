use ark_std::{start_timer, end_timer};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{self, Circuit, ConstraintSystem, Error},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use rand::rngs::OsRng;
use snark_verifier::{
    loader::{self, native::NativeLoader, halo2::halo2_wrong_ecc::{self, maingate::{MainGateConfig, RangeConfig, MainGate, RangeChip, RegionCtx, RangeInstructions, MainGateInstructions}, EccConfig, integer::rns::Rns}},
    pcs::{
        kzg::{KzgAccumulator, KzgSuccinctVerifyingKey, LimbsEncodingInstructions, KzgAs, Gwc19, LimbsEncoding},
        AccumulationScheme, AccumulationSchemeProver,
    },
    system,
    util::arithmetic::{fe_to_limbs, PrimeField},
    verifier::{plonk::PlonkProtocol, SnarkVerifier, self},
};
use std::rc::Rc;

/// Number of limbs to decompose a elliptic curve base field element into.
const LIMBS: usize = 4;
/// Number of bits of each decomposed limb.
const BITS: usize = 68;

/// KZG accumulation scheme with GWC19 multiopen.
type As = KzgAs<Bn256, Gwc19>;
/// Plonk succinct verifier with `KzgAs`
type PlonkSuccinctVerifier = verifier::plonk::PlonkSuccinctVerifier<As, LimbsEncoding<LIMBS, BITS>>;
/// Plonk verifier with `KzgAs` and `LimbsEncoding<LIMBS, BITS>`.
pub type PlonkVerifier = verifier::plonk::PlonkVerifier<As, LimbsEncoding<LIMBS, BITS>>;

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 60;

/// KZG succinct verifying key
type Svk = KzgSuccinctVerifyingKey<G1Affine>;
/// for `Halo2Loader`.
type BaseFieldEccChip = halo2_wrong_ecc::BaseFieldEccChip<G1Affine, LIMBS, BITS>;
/// `Halo2Loader` with hardcoded `EccChip`.
type Halo2Loader<'a> = loader::halo2::Halo2Loader<'a, G1Affine, BaseFieldEccChip>;
/// `PoseidonTranscript` with hardcoded parameter with 128-bits security.
pub type PoseidonTranscript<L, S> =
    system::halo2::transcript::halo2::PoseidonTranscript<G1Affine, L, S, T, RATE, R_F, R_P>;

/// Snark contains the minimal information for verification
pub struct Snark {
    protocol: PlonkProtocol<G1Affine>,
    instances: Vec<Vec<Fr>>,
    proof: Vec<u8>,
}

impl Snark {
    /// Construct `Snark` with each field.
    pub fn new(
        protocol: PlonkProtocol<G1Affine>,
        instances: Vec<Vec<Fr>>,
        proof: Vec<u8>,
    ) -> Self {
        Self {
            protocol,
            instances,
            proof,
        }
    }
}

impl From<Snark> for SnarkWitness {
    fn from(snark: Snark) -> Self {
        Self {
            protocol: snark.protocol,
            instances: snark
                .instances
                .into_iter()
                .map(|instances| instances.into_iter().map(Value::known).collect_vec())
                .collect(),
            proof: Value::known(snark.proof),
        }
    }
}

/// SnarkWitness
#[derive(Clone)]
pub struct SnarkWitness {
    protocol: PlonkProtocol<G1Affine>,
    instances: Vec<Vec<Value<Fr>>>,
    proof: Value<Vec<u8>>,
}

impl SnarkWitness {
    /// Returns `SnarkWitness` with all witness as `Value::unknown()`.
    fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol.clone(),
            instances: self
                .instances
                .iter()
                .map(|instances| vec![Value::unknown(); instances.len()])
                .collect(),
            proof: Value::unknown(),
        }
    }

    fn proof(&self) -> Value<&[u8]> {
        self.proof.as_ref().map(Vec::as_slice)
    }
}

/// Aggregate snarks into a single accumulator and decompose it into
/// `4 * LIMBS` limbs.
/// Fail if any given snarks is invalid.
pub fn aggregate<'a>(
    svk: &Svk,
    loader: &Rc<Halo2Loader<'a>>,
    snarks: &[SnarkWitness],
    as_proof: Value<&'_ [u8]>,
) -> KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
    let assign_instances = |instances: &[Vec<Value<Fr>>]| {
        instances
            .iter()
            .map(|instances| {
                instances
                    .iter()
                    .map(|instance| loader.assign_scalar(*instance))
                    .collect_vec()
            })
            .collect_vec()
    };

    let accumulators = snarks
        .iter()
        .flat_map(|snark| {
            let protocol = snark.protocol.loaded(loader);
            let instances = assign_instances(&snark.instances);
            let mut transcript =
                PoseidonTranscript::<Rc<Halo2Loader>, _>::new(loader, snark.proof());
            let proof =
                PlonkSuccinctVerifier::read_proof(svk, &protocol, &instances, &mut transcript)
                    .unwrap();
            PlonkSuccinctVerifier::verify(svk, &protocol, &instances, &proof).unwrap()
        })
        .collect_vec();

    let acccumulator = {
        let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::new(loader, as_proof);
        let proof =
            As::read_proof(&Default::default(), &accumulators, &mut transcript).unwrap();
        As::verify(&Default::default(), &accumulators, &proof).unwrap()
    };

    acccumulator
}

#[derive(Clone)]
pub struct AggregationConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl AggregationConfig {
    /// Configure for `MainGate` and `RangeChip` with corresponding fixed lookup
    /// table.
    pub fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        composition_bits: Vec<usize>,
        overflow_bits: Vec<usize>,
    ) -> Self {
        let main_gate_config = MainGate::<F>::configure(meta);
        let range_config =
            RangeChip::<F>::configure(meta, &main_gate_config, composition_bits, overflow_bits);
        AggregationConfig {
            main_gate_config,
            range_config,
        }
    }

    /// Returns `MainGate`.
    pub fn main_gate(&self) -> MainGate<Fr> {
        MainGate::new(self.main_gate_config.clone())
    }

    /// Returns `RangeChip`.
    pub fn range_chip(&self) -> RangeChip<Fr> {
        RangeChip::new(self.range_config.clone())
    }

    /// Returns `EccChip`.
    pub fn ecc_chip(&self) -> BaseFieldEccChip {
        BaseFieldEccChip::new(EccConfig::new(
            self.range_config.clone(),
            self.main_gate_config.clone(),
        ))
    }
}

#[derive(Clone)]
pub struct AggregationCircuit {
    svk: Svk,
    snarks: Vec<SnarkWitness>,
    instances: Vec<Fr>,
    as_proof: Value<Vec<u8>>,
}

impl AggregationCircuit {
    /// Create an Aggregation circuit with aggregated accumulator computed.
    pub fn new(params: &ParamsKZG<Bn256>, snarks: impl IntoIterator<Item = Snark>) -> Self {
        let svk = params.get_g()[0].into();
        let snarks = snarks.into_iter().collect_vec();

        let accumulators = snarks
            .iter()
            .flat_map(|snark| {
                let mut transcript =
                    PoseidonTranscript::<NativeLoader, _>::new(snark.proof.as_slice());
                let proof = PlonkSuccinctVerifier::read_proof(
                    &svk,
                    &snark.protocol,
                    &snark.instances,
                    &mut transcript,
                )
                .unwrap();
                PlonkSuccinctVerifier::verify(&svk, &snark.protocol, &snark.instances, &proof)
                    .unwrap()
            })
            .collect_vec();

        // Create a proof that argues if old AccumulationScheme::Accumulators are properly accumulated into the new one, and returns the new one as output.
        let (accumulator, as_proof) = {
            let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(Vec::new());
            let accumulator =
                As::create_proof(&Default::default(), &accumulators, &mut transcript, OsRng)
                    .unwrap();
            (accumulator, transcript.finalize())
        };

        let KzgAccumulator { lhs, rhs } = accumulator;
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<_, _, LIMBS, BITS>)
            .concat();

        Self {
            svk,
            snarks: snarks.into_iter().map_into().collect(),
            instances,
            as_proof: Value::known(as_proof),
        }
    }

    /// Returns accumulator indices in instance columns, which will be in
    /// the last 4 * LIMBS rows of MainGate's instance column.
    pub fn accumulator_indices() -> Vec<(usize, usize)> {
        (0..4 * LIMBS).map(|idx| (0, idx)).collect()
    }

    /// Returns number of instance
    pub fn num_instance() -> Vec<usize> {
        vec![4 * LIMBS]
    }

    /// Returns instances
    pub fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }

    pub fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }
}

impl Circuit<Fr> for AggregationCircuit {
    type Config = AggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            svk: self.svk,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
            instances: Vec::new(),
            as_proof: Value::unknown(),
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
        AggregationConfig::configure(
            meta,
            vec![BITS / LIMBS],
            Rns::<Fq, Fr, LIMBS, BITS>::construct().overflow_lengths(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        let main_gate = config.main_gate();
        let range_chip = config.range_chip();

        range_chip.load_table(&mut layouter)?;

        let accumulator_limbs = layouter.assign_region(
            || "",
            |region| {
                let ctx = RegionCtx::new(region, 0);

                let ecc_chip = config.ecc_chip();
                let loader = Halo2Loader::new(ecc_chip, ctx);
                let accumulator = aggregate(&self.svk, &loader, &self.snarks, self.as_proof());

                let accumulator_limbs = [accumulator.lhs, accumulator.rhs]
                    .iter()
                    .map(|ec_point| {
                        loader.ecc_chip().assign_ec_point_to_limbs(
                            &mut loader.ctx_mut(),
                            ec_point.assigned(),
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()?
                    .into_iter()
                    .flatten();

                Ok(accumulator_limbs)
            },
        )?;

        for (row, limb) in accumulator_limbs.enumerate() {
            main_gate.expose_public(layouter.namespace(|| ""), limb, row)?;
        }

        Ok(())
    }
}
