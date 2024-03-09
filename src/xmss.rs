use crate::hashers::Hashers;
use crate::types::{Adrs, XmssSig, TREE, WOTS_HASH};
use crate::wots;
use generic_array::{ArrayLength, GenericArray};


/// Algorithm 8: `xmss_node(SK.seed, i, z, PK.seed, ADRS)` on page 22.
/// Compute the root of a Merkle subtree of WOTS+ public keys.
///
/// Input: Secret seed `SK.seed`, target node index `i`, target node height `z`, public seed `PK.seed`,
/// `address ADRS`. <br>
/// Output: n-byte root `node`.
#[allow(clippy::similar_names)] // sk_seed and pk_seed
pub(crate) fn xmss_node<
    H: ArrayLength,
    HP: ArrayLength,
    K: ArrayLength,
    LEN: ArrayLength,
    M: ArrayLength,
    N: ArrayLength,
>(
    hashers: &Hashers<K, LEN, M, N>, sk_seed: &[u8], i: u32, z: u32, pk_seed: &[u8], adrs: &Adrs,
) -> Result<GenericArray<u8, N>, &'static str> {
    let mut adrs = adrs.clone();

    // 1: if z > h′ or i ≥ 2^{h −z} then
    if (z > HP::to_u32()) | (u64::from(i) >= 2u64.pow(HP::to_u32() - z)) {
        //
        // 2: return NULL
        return Err("Alg8: fail");

        // 3: end if
    }

    // 4: if z = 0 then
    let node = if z == 0 {
        //
        // 5: ADRS.setTypeAndClear(WOTS_HASH)
        adrs.set_type_and_clear(WOTS_HASH);

        // 6: ADRS.setKeyPairAddress(i)
        adrs.set_key_pair_address(i);

        // 7: node ← wots_PKgen(SK.seed, PK.seed, ADRS)
        wots::wots_pkgen::<K, LEN, M, N>(hashers, sk_seed, pk_seed, &adrs)?
            .0
            .clone()

        // 8: else
    } else {
        //
        // 9: lnode ← xmss_node(SK.seed, 2 * i, z − 1, PK.seed, ADRS)
        let lnode =
            xmss_node::<H, HP, K, LEN, M, N>(hashers, sk_seed, 2 * i, z - 1, pk_seed, &adrs)?;

        // 10: rnode ← xmss_node(SK.seed, 2 * i + 1, z − 1, PK.seed, ADRS)
        let rnode =
            xmss_node::<H, HP, K, LEN, M, N>(hashers, sk_seed, 2 * i + 1, z - 1, pk_seed, &adrs)?;

        // 11: ADRS.setTypeAndClear(TREE)
        adrs.set_type_and_clear(TREE);

        // 12: ADRS.setTreeHeight(z)
        adrs.set_tree_height(z);

        // 13: ADRS.setTreeIndex(i)
        adrs.set_tree_index(i);

        // 14: node ← H(PK.seed, ADRS, lnode ∥ rnode)
        (hashers.h)(pk_seed, &adrs, &lnode, &rnode)

        // 15: end if
    };

    // 16: return node
    Ok(node)
}


/// Algorithm 9: `xmss_sign(M, SK.seed, idx, PK.seed, ADRS)` on page 23.
/// Generate an XMSS signature.
///
/// Input: n-byte message `M`, secret seed `SK.seed`, index `idx`, public seed `PK.seed`, address `ADRS`. <br>
/// Output: XMSS signature SIGXMSS = (sig ∥ AUTH).
#[allow(clippy::similar_names)] // sk_seed and pk_seed
pub(crate) fn xmss_sign<
    H: ArrayLength,
    HP: ArrayLength,
    K: ArrayLength,
    LEN: ArrayLength,
    M: ArrayLength,
    N: ArrayLength,
>(
    hashers: &Hashers<K, LEN, M, N>, m: &[u8], sk_seed: &[u8], idx: u32, pk_seed: &[u8],
    adrs: &Adrs,
) -> Result<XmssSig<HP, LEN, N>, &'static str> {
    let mut adrs = adrs.clone();
    let mut sig_xmss = XmssSig::default();

    // 1: for j from 0 to h′-1 do    ▷ Build authentication path
    for j in 0..HP::to_u32() {
        //
        // 2: k ← idx/2 ^j xor 1
        let k = (idx >> j) ^ 1;

        // 3: AUTH[j] ← xmss_node(SK.seed, k, j, PK.seed, ADRS)
        sig_xmss.auth[j as usize] =
            xmss_node::<H, HP, K, LEN, M, N>(hashers, sk_seed, k, j, pk_seed, &adrs)?;

        // 4: end for
    }

    // 5:
    // 6: ADRS.setTypeAndClear(WOTS_HASH)
    adrs.set_type_and_clear(WOTS_HASH);

    // 7: ADRS.setKeyPairAddress(idx)
    adrs.set_key_pair_address(idx);

    // 8: sig ← wots_sign(M, SK.seed, PK.seed, ADRS)
    sig_xmss.sig_wots = wots::wots_sign::<K, LEN, M, N>(hashers, m, sk_seed, pk_seed, &adrs); // TODO: polish out BB!

    // 9: SIG_XMSS ← sig ∥ AUTH
    // struct built above

    // 10: return SIG_XMSS
    Ok(sig_xmss)
}


/// Algorithm 10: `xmss_PKFromSig(idx, SIG_XMSS, M, PK.seed, ADRS)`
/// Compute an XMSS public key from an XMSS signature.
///
/// Input: Index `idx`, XMSS signature `SIG_XMSS = (sig ∥ AUTH)`, n-byte message `M`, public seed `PK.seed`,
/// address `ADRS`. <br>
/// Output: n-byte root value `node[0]`.
pub(crate) fn xmss_pk_from_sig<
    HP: ArrayLength,
    K: ArrayLength,
    LEN: ArrayLength,
    M: ArrayLength,
    N: ArrayLength,
>(
    hashers: &Hashers<K, LEN, M, N>, idx: u32, sig_xmss: &XmssSig<HP, LEN, N>, m: &[u8],
    pk_seed: &[u8], adrs: &Adrs,
) -> GenericArray<u8, N> {
    let mut adrs = adrs.clone();

    // 1: ADRS.setTypeAndClear(WOTS_HASH)    ▷ Compute WOTS+ pk from WOTS+ sig
    adrs.set_type_and_clear(WOTS_HASH);

    // 2: ADRS.setKeyPairAddress(idx)
    adrs.set_key_pair_address(idx);

    // 3: sig ← SIG_XMSS.getWOTSSig()    ▷ SIG_XMSS [0 : len · n]
    let sig = sig_xmss.get_wots_sig();

    // 4: AUTH ← SIG_XMSS.getXMSSAUTH()    ▷ SIG_XMSS [len · n : (len + h′) · n]
    let auth = sig_xmss.get_xmss_auth();

    // 5: node[0] ← wots_PKFromSig(sig, M, PK.seed, ADRS)
    let mut node_0 = wots::wots_pk_from_sig::<K, LEN, M, N>(hashers, sig, m, pk_seed, &adrs)
        .0
        .clone();

    // 6:
    // 7: ADRS.setTypeAndClear(TREE)    ▷ Compute root from WOTS+ pk and AUTH
    adrs.set_type_and_clear(TREE);

    // 8: ADRS.setTreeIndex(idx)
    adrs.set_tree_index(idx);

    // 9: for k from 0 to h′ − 1 do
    for k in 0..HP::to_u32() {
        //
        // 10: ADRS.setTreeHeight(k + 1)
        adrs.set_tree_height(k + 1);

        // 11: if idx/2^k is even then
        let node_1 = if ((idx >> k) & 1) == 0 {
            //
            // 12: ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
            let tmp = adrs.get_tree_index() / 2;
            adrs.set_tree_index(tmp);

            // 13: node[1] ← H(PK.seed, ADRS, node[0] ∥ AUTH[k])
            (hashers.h)(pk_seed, &adrs, &node_0, &auth[k as usize])

            // 14: else
        } else {
            //
            // 15: ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
            let tmp = (adrs.get_tree_index() - 1) / 2;
            adrs.set_tree_index(tmp);

            // 16: node[1] ← H(PK.seed, ADRS, AUTH[k] ∥ node[0])
            (hashers.h)(pk_seed, &adrs, &auth[k as usize], &node_0)

            // 17: end if
        };

        // 18: node[0] ← node[1]
        node_0 = node_1;

        // 19: end for
    }

    // 20: return node[0]
    node_0
}
