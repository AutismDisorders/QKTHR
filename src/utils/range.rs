#![allow(dead_code)]
use rand::Rng;

/// Generate a random number in the range [0, hi]
pub fn random_range(hi: u64) -> u64 {
    let mut rng = rand::thread_rng();
    rng.gen_range(0..=hi)
}
