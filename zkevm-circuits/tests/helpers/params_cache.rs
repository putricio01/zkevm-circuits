// tests/helpers/params_cache.rs (new helper)
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::poly::commitment::Params;
use rand::{rngs::StdRng, SeedableRng};
use std::{fs, path::Path};

pub fn load_or_build_params_k18() -> ParamsKZG<Bn256> {
    let path = Path::new("./.cache/params_k18.bin");
    if let Ok(bytes) = fs::read(path) {
        let mut rdr = &bytes[..];
        return ParamsKZG::<Bn256>::read(&mut rdr).expect("read params");
    }
    fs::create_dir_all("./.cache").ok();
    let mut rng = StdRng::from_entropy();               // non-blocking CSPRNG
    let params = ParamsKZG::<Bn256>::setup(18, &mut rng);
    let mut buf = vec![];
    params.write(&mut buf).expect("write params");
    fs::write(path, &buf).ok();
    params
}
