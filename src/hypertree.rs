use crate::hashers::Hashers;
use crate::types::{Adrs, HtSig};
use crate::xmss;
use generic_array::{ArrayLength, GenericArray};


/// Algorithm 11: `ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf)` on page 27.
/// Generate a hypertree signature.
///
/// Input: Message `M`, private seed `SK.seed`, public seed `PK.seed`, tree index `idx_tree`, leaf
/// index `idx_leaf`. <br>
/// Output: HT signature `SIG_HT`.
#[allow(clippy::similar_names)] // sk_seed and pk_seed
pub(crate) fn ht_sign<
    D: ArrayLength,
    H: ArrayLength,
    HP: ArrayLength,
    K: ArrayLength,
    LEN: ArrayLength,
    M: ArrayLength,
    N: ArrayLength,
>(
    hashers: &Hashers<K, LEN, M, N>, m: &[u8], sk_seed: &[u8], pk_seed: &[u8], idx_tree: u64,
    idx_leaf: u32,
) -> Result<HtSig<D, HP, LEN, N>, &'static str> {
    let mut idx_tree = idx_tree;
    //
    // 1: ADRS ← toByte(0, 32)
    let mut adrs = Adrs::default();

    // 2:
    // 3: ADRS.setTreeAddress(idxtree)
    adrs.set_tree_address(idx_tree);

    // 4: SIG_tmp ← xmss_sign(M, SK.seed, idxleaf, PK.seed, ADRS)
    let mut sig_tmp =
        xmss::xmss_sign::<H, HP, K, LEN, M, N>(hashers, m, sk_seed, idx_leaf, pk_seed, &adrs)?;

    // 5: SIG_HT ← SIG_tmp
    let mut sig_ht = HtSig::default();
    sig_ht.xmss_sigs[0] = sig_tmp.clone();

    // 6: root ← xmss_PKFromSig(idx_leaf, SIG_tmp, M, PK.seed, ADRS)
    let mut root =
        xmss::xmss_pk_from_sig::<HP, K, LEN, M, N>(hashers, idx_leaf, &sig_tmp, m, pk_seed, &adrs);

    // 7: for j from 1 to d − 1 do
    for j in 1..D::to_u32() {
        //
        // 8: idx_leaf ← idx_tree mod 2^{h′}    ▷ h′ least significant bits of idx_tree
        let idx_leaf = u32::try_from(idx_tree % 2u64.pow(HP::to_u32()))
            .map_err(|_| "Alg11: oversized idx leaf")?;

        // 9: idx_tree ← idx_tree ≫ h′    ▷ Remove least significant h′ bits from idx_tree
        idx_tree >>= HP::to_u32();

        // 10: ADRS.setLayerAddress(j)
        adrs.set_layer_address(j);

        // 11: ADRS.setTreeAddress(idx_tree)
        adrs.set_tree_address(idx_tree);

        // 12: SIG_tmp ← xmss_sign(root, SK.seed, idx_leaf, PK.seed, ADRS)
        sig_tmp = xmss::xmss_sign::<H, HP, K, LEN, M, N>(
            hashers, &root, sk_seed, idx_leaf, pk_seed, &adrs,
        )?;

        // 13: SIG_HT ← SIG_HT ∥ SIG_tmp
        sig_ht.xmss_sigs[j as usize] = sig_tmp.clone();

        // 14: if j < d − 1 then
        if j < (D::to_u32() - 1) {
            //
            // 15: root ← xmss_PKFromSig(idx_leaf, SIG_tmp, root, PK.seed, ADRS)
            root = xmss::xmss_pk_from_sig::<HP, K, LEN, M, N>(
                hashers, idx_leaf, &sig_tmp, &root, pk_seed, &adrs,
            );

            // 16: end if
        }

        // 17: end for
    }

    // 18: return SIGHT
    Ok(sig_ht)
}


/// Algorithm 12: `ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)` on page 28.
/// Verify a hypertree signature.
///
/// Input: Message `M`, signature `SIG_HT`, public seed `PK.seed`, tree index `idx_tree`, leaf index `idx_leaf`,
/// HT public key `PK.root`. <br>
/// Output: Boolean.
pub(crate) fn ht_verify<
    D: ArrayLength,
    HP: ArrayLength,
    K: ArrayLength,
    LEN: ArrayLength,
    M: ArrayLength,
    N: ArrayLength,
>(
    hashers: &Hashers<K, LEN, M, N>, m: &[u8], sig_ht: &HtSig<D, HP, LEN, N>, pk_seed: &[u8],
    idx_tree: u64, idx_leaf: u32, pk_root: &GenericArray<u8, N>,
) -> bool {
    let mut idx_tree = idx_tree;
    //
    // 1: ADRS ← toByte(0, 32)
    let mut adrs = Adrs::default();

    // 2:
    // 3: ADRS.setTreeAddress(idx_tree)
    adrs.set_tree_address(idx_tree);

    // 4: SIG_tmp ← SIG_HT.getXMSSSignature(0)    ▷ SIG_HT [0 : (h′ + len) · n]
    let sig_tmp = sig_ht.xmss_sigs[0].clone();

    // 5: node ← xmss_PKFromSig(idx_leaf, SIG_tmp, M, PK.seed, ADRS)
    let mut node = xmss::xmss_pk_from_sig(hashers, idx_leaf, &sig_tmp, m, pk_seed, &adrs);

    // 6: for j from 1 to d − 1 do
    for j in 1..D::to_u32() {
        //
        // 7: idx_leaf ← idx_tree mod 2^{h′}    ▷ h′ least significant bits of idx_tree
        let idx_leaf = u32::try_from(idx_tree % 2u64.pow(HP::to_u32())); // TODO: clean
        if idx_leaf.is_err() {
            return false;
        };
        let idx_leaf = idx_leaf.unwrap();

        // 8: idx_tree ← idx_tree ≫ h′    ▷ Remove least significant h′ bits from idx_tree
        idx_tree >>= HP::to_u32();

        // 9: ADRS.setLayerAddress(j)
        adrs.set_layer_address(j);

        // 10: ADRS.setTreeAddress(idx_tree)
        adrs.set_tree_address(idx_tree);

        // 11: SIG_tmp ← SIG_HT.getXMSSSignature(j)     ▷ SIGHT [ j · (h′ + len) · n : ( j + 1)(h′ + len) · n]
        let sig_tmp = sig_ht.xmss_sigs[j as usize].clone();

        // 12: node ← xmss_PKFromSig(idx_leaf, SIG_tmp, node, PK.seed, ADRS)
        node = xmss::xmss_pk_from_sig(hashers, idx_leaf, &sig_tmp, &node, pk_seed, &adrs);

        // 13: end for
    }

    // 14: if node = PK.root then
    // 15:   return true
    // 16: else
    // 17:   return false
    // 18: end if
    node == *pk_root // TODO: CT equal
}
