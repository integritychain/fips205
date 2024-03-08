use crate::hashers::Hashers;
use crate::types::FORS_TREE;
use crate::types::{Adrs, SlhDsaSig, SlhPrivateKey, SlhPublicKey};
use crate::{fors, helpers, hypertree, xmss};
use generic_array::{ArrayLength, GenericArray};
use rand_core::CryptoRngCore;


/// Algorithm 17: `slh_keygen()` on page 34.
/// Generate an SLH-DSA key pair.
///
/// Input: (none) <br>
/// Output: SLH-DSA key pair `(SK, PK)`.
#[allow(clippy::similar_names)] // sk_seed and pk_seed
pub(crate) fn slh_keygen_with_rng<
    D: ArrayLength,
    H: ArrayLength,
    HP: ArrayLength,
    K: ArrayLength,
    LEN: ArrayLength,
    M: ArrayLength,
    N: ArrayLength,
>(
    rng: &mut impl CryptoRngCore, hashers: &Hashers<K, LEN, M, N>,
) -> Result<(SlhPrivateKey<N>, SlhPublicKey<N>), &'static str> {
    //
    // 1: SK.seed ←$ B^n    ▷ Set SK.seed, SK.prf, and PK.seed to random n-byte
    let mut sk_seed = GenericArray::default();
    rng.try_fill_bytes(&mut sk_seed)
        .map_err(|_| "Alg17: rng failed1")?;

    // 2: SK.prf ←$ B^n    ▷ strings using an approved random bit generator
    let mut sk_prf = GenericArray::default();
    rng.try_fill_bytes(&mut sk_prf)
        .map_err(|_| "Alg17: rng failed2")?;

    // 3: PK.seed ←$ B^n
    let mut pk_seed = GenericArray::default();
    rng.try_fill_bytes(&mut pk_seed)
        .map_err(|_| "Alg17: rng failed3")?;

    // 4:
    // 5: ADRS ← toByte(0, 32)    ▷ Generate the public key for the top-level XMSS tree
    let mut adrs = Adrs::default();

    // 6: ADRS.setLayerAddress(d − 1)
    adrs.set_layer_address(D::to_u32() - 1);

    // 7: PK.root ← xmss_node(SK.seed, 0, h′, PK.seed, ADRS)
    let pk_root = xmss::xmss_node::<H, HP, K, LEN, M, N>(
        hashers,
        &sk_seed,
        0,
        HP::to_u32(),
        &pk_seed,
        &adrs,
    )?;

    // 8:
    // 9: return ( (SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root) )
    let pk = SlhPublicKey { pk_seed: pk_seed.clone(), pk_root: pk_root.clone() };
    let sk = SlhPrivateKey { sk_seed, sk_prf, pk_seed, pk_root };
    Ok((sk, pk))
}


/// Algorithm 18: `slh_sign(M, SK)` on page 35.
/// Generate an SLH-DSA signature.
///
/// Input: Message `M`, private key `SK = (SK.seed, SK.prf, PK.seed, PK.root)`. <br>
/// Output: SLH-DSA signature `SIG`.
#[allow(clippy::cast_possible_truncation)] // temporary, investigating idx_leaf int sizes
pub(crate) fn slh_sign_with_rng<
    A: ArrayLength,
    D: ArrayLength,
    H: ArrayLength,
    HP: ArrayLength,
    K: ArrayLength,
    LEN: ArrayLength,
    M: ArrayLength,
    N: ArrayLength,
>(
    rng: &mut impl CryptoRngCore, hashers: &Hashers<K, LEN, M, N>, m: &[u8], sk: &SlhPrivateKey<N>,
    randomize: bool,
) -> Result<SlhDsaSig<A, D, HP, K, LEN, N>, &'static str> {
    //
    // 1: ADRS ← toByte(0, 32)
    let mut adrs = Adrs::default();

    // 2:
    // 3: opt_rand ← PK.seed    ▷ Set opt_rand to either PK.seed
    let mut opt_rand = sk.pk_seed.clone();

    // 4: if (RANDOMIZE) then    ▷ or to a random n-byte string
    if randomize {
        // 5: opt_rand ←$ Bn
        rng.try_fill_bytes(&mut opt_rand)
            .map_err(|_| "Alg17: rng failed")?;

        // 6: end if
    }

    // 7: R ← PRF_msg(SK.prf, opt_rand, M)    ▷ Generate randomizer
    let r = (hashers.prf_msg)(&sk.sk_prf, &opt_rand, m);

    // 8: SIG ← R
    let mut sig = SlhDsaSig::default();
    sig.randomness = r.clone();

    // 9:
    // 10: digest ← H_msg(R, PK.seed, PK.root, M)    ▷ Compute message digest
    let digest = (hashers.h_msg)(&r, &sk.pk_seed, &sk.pk_root, m);

    // 11: md ← digest[0 : ceil(k·a/8)]    ▷ first ceil(k·a/8) bytes
    let index1 = (K::to_usize() * A::to_usize() + 7) / 8;
    let md = &digest[0..index1];

    // 12: tmp_idx_tree ← digest[ceil(k·a/8) : ceil(k·a/8) + ceil((h-h/d)/8)]    ▷ next ceil((h-h/d)/8) bytes
    let index2 = index1 + (H::to_usize() - H::to_usize() / D::to_usize() + 7) / 8;
    let tmp_idx_tree = &digest[index1..index2];

    // 13: tmp_idx_leaf ← digest[ceil(k·a/8) + ceil((h-h/d)/8) : ceil(k·a/8) + ceil((h-h/d)/8) + ceil(h/8d)]    ▷ next ceil(h/8d) bytes
    let index3 = index2 + (H::to_usize() + 8 * D::to_usize() - 1) / (8 * D::to_usize());
    let tmp_idx_leaf = &digest[index2..index3];

    // 14:
    // 15: idx_tree ← toInt(tmp_idx_tree, ceil((h-h/d)/8)) mod 2^{h−h/d}
    let idx_tree =
        helpers::to_int(tmp_idx_tree, (H::to_u32() - H::to_u32() / D::to_u32() + 7) / 8)
            & (u64::MAX >> (64 - (H::to_u32() - H::to_u32() / D::to_u32())));

    // 16: idx_leaf ← toInt(tmp_idx_leaf, ceil(h/8d) mod 2^{h/d}
    let idx_leaf = helpers::to_int(tmp_idx_leaf, (H::to_u32() + 8 * D::to_u32() - 1) / (8 * D::to_u32()))
        & (u64::MAX >> (64 - H::to_u32() / D::to_u32()));

    // 17:
    // 18: ADRS.setTreeAddress(idx_tree)
    adrs.set_tree_address(idx_tree);

    // 19: ADRS.setTypeAndClear(FORS_TREE)
    adrs.set_type_and_clear(FORS_TREE);

    // 20: ADRS.setKeyPairAddress(idxleaf)
    adrs.set_key_pair_address(idx_leaf as u32);

    // 21: SIG_FORS ← fors_sign(md, SK.seed, PK.seed, ADRS)
    // 22: SIG ← SIG ∥ SIG_FORS
    sig.fors_sig = fors::fors_sign(hashers, md, &sk.sk_seed, &adrs, &sk.pk_seed)?;

    // 23:
    // 24: PK_FORS ← fors_pkFromSig(SIG_FORS , md, PK.seed, ADRS)    ▷ Get FORS key
    let pk_fors =
        fors::fors_pk_from_sig::<A, K, LEN, M, N>(hashers, &sig.fors_sig, md, &sk.pk_seed, &adrs);

    // 25:
    // 26: SIG_HT ← ht_sign(PK_FORS , SK.seed, PK.seed, idx_tree, idx_leaf)
    // 27: SIG ← SIG ∥ SIG_HT
    sig.ht_sig = hypertree::ht_sign::<D, H, HP, K, LEN, M, N>(
        hashers,
        &pk_fors.key,
        &sk.sk_seed,
        &sk.pk_seed,
        idx_tree,
        idx_leaf as u32,
    )?;

    // 28: return SIG
    Ok(sig)
}


/// Algorithm 19: `slh_verify(M, SIG, PK)`
/// Verify an SLH-DSA signature.
///
/// Input: Message `M`, signature `SIG`, public key `PK = (PK.seed, PK.root)`. <br>
/// Output: Boolean.
#[allow(clippy::cast_possible_truncation)] // TODO: temporary
pub(crate) fn slh_verify<
    A: ArrayLength,
    D: ArrayLength,
    H: ArrayLength,
    HP: ArrayLength,
    K: ArrayLength,
    LEN: ArrayLength,
    M: ArrayLength,
    N: ArrayLength,
>(
    hashers: &Hashers<K, LEN, M, N>, m: &[u8], sig: &SlhDsaSig<A, D, HP, K, LEN, N>,
    pk: &SlhPublicKey<N>,
) -> bool {
    // 1: if |SIG| != (1 + k(1 + a) + h + d · len) · n then
    // 2:   return false
    // 3: end if
    // The above size is performed in the wrapper/adapter deserialize function

    // 4: ADRS ← toByte(0, 32)
    let mut adrs = Adrs::default();

    // 5: R ← SIG.getR()    ▷ SIG[0 : n]
    let r = &sig.randomness;

    // 6: SIG_FORS ← SIG.getSIG_FORS()    ▷ SIG[n : (1 + k(1 + a)) · n]
    let sig_fors = &sig.fors_sig;

    // 7: SIG_HT ← SIG.getSIG_HT()    ▷ SIG[(1 + k(1 + a)) · n : (1 + k(1 + a) + h + d · len) · n]
    let sig_ht = &sig.ht_sig;

    // 8:
    // 9: digest ← Hmsg(R, PK.seed, PK.root, M)    ▷ Compute message digest
    let digest = (hashers.h_msg)(r, &pk.pk_seed, &pk.pk_root, m);

    // 10: md ← digest[0 : ceil(k·a/8)]    ▷ first ceil(k·a/8) bytes
    let index1 = (K::to_usize() * A::to_usize() + 7) / 8;
    let md = &digest[0..index1];

    // 11: tmp_idx_tree ← digest[ceil(k·a/8) : ceil(k·a/8) + ceil((h - h/d)/8)]     ▷ next ceil((h - h/d)/8) bytes
    let index2 = index1 + (H::to_usize() - H::to_usize() / D::to_usize() + 7) / 8;
    let tmp_idx_tree = &digest[index1..index2];

    // 12: tmp_idx_leaf ← digest[ceil(k·a/8) + ceil((h - h/d)/8) : ceil(k·a/8) + ceil((h - h/d)/8) + ceil(h/8d)]  ▷ next ceil(h/8d) bytes
    let index3 = index2 + (H::to_usize() + 8 * D::to_usize() - 1) / (8 * D::to_usize());
    let tmp_idx_leaf = &digest[index2..index3];

    // 13:
    // 14: idx_tree ← toInt(tmp_idx_tree, ceil((h - h/d)/8)) mod 2^{h−h/d}
    let idx_tree =
        helpers::to_int(tmp_idx_tree, (H::to_u32() - H::to_u32() / D::to_u32() + 7) /8)
            & (u64::MAX >> (64 - (H::to_u32() - H::to_u32() / D::to_u32())));

    // 15: idx_leaf ← toInt(tmp_idx_leaf, ceil(h/8d) mod 2^{h/d}
    let idx_leaf = helpers::to_int(tmp_idx_leaf, (H::to_u32() + 8 * D::to_u32() - 1) / (8 * D::to_u32()))
        & (u64::MAX >> (64 - H::to_u32() / D::to_u32()));

    // 16:
    // 17: ADRS.setTreeAddress(idx_tree)    ▷ Compute FORS public key
    adrs.set_tree_address(idx_tree);

    // 18: ADRS.setTypeAndClear(FORS_TREE)
    adrs.set_type_and_clear(FORS_TREE);

    // 19: ADRS.setKeyPairAddress(idx_leaf)
    adrs.set_key_pair_address(idx_leaf as u32);

    // 20:
    // 21: PK_FORS ← fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)
    let pk_fors =
        fors::fors_pk_from_sig::<A, K, LEN, M, N>(hashers, sig_fors, md, &pk.pk_seed, &adrs);


    // 22:
    // 23: return ht_verify(PK_FORS, SIG_HT, PK.seed, idx_tree , idx_leaf, PK.root)
    hypertree::ht_verify::<D, HP, K, LEN, M, N>(
        hashers,
        &pk_fors.key,
        sig_ht,
        &pk.pk_seed,
        idx_tree,
        idx_leaf as u32,
        &pk.pk_root,
    )
}
