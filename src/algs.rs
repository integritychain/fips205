use crate::types::{ADRS, WotsSig};
use crate::types::{WOTS_PK, WOTS_PRF};
use crate::Context;
use alloc::vec;
use alloc::vec::Vec;
use generic_array::{ArrayLength, GenericArray};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Algorithm 1: `toInt(X, n)` on page 14.
/// Convert a byte string to an integer.
///
/// Input: n-byte string `X`. <br>
/// Output: Integer value of `X`.
pub(crate) fn to_int(x: &[u8], n: usize) -> u64 {
    assert_eq!(x.len(), n);
    // 1: total ← 0
    let mut total = 0_u64;
    // 2:
    // 3: for i from 0 to n − 1 do
    for i in 0..n {
        // 4:   total ← 256 · total + X[i]
        total = (total << 8) + x[i] as u64;
        // 5: end for
    }
    // 6: return total
    total
}


/// Algorithm 2: `toByte(x, n)` on page 15.
/// Convert an integer to a byte string.
///
/// Input: Integer `x`, string length `n`. <br>
/// Output: Byte string of length `n` containing binary representation of `x` in big-endian byte-order.
pub(crate) fn to_byte(x: u64, n: usize) -> Vec<u8> {
    let mut s = vec![0u8; n];

    // 1: total ← x
    let mut total = x;

    // 2:

    // 3: for i from 0 to n − 1 do
    for i in 0..n {
        //
        // 4:   S[n − 1 − i] ← total mod 256    ▷ Least significant 8 bits of total
        s[n - 1 - i] = total as u8;

        // 5:   total ← total ≫ 8
        total >>= 8;

        // 6: end for
    }

    // 7: return S
    s
}


/// Algorithm 3: `base_2^b(X, b, out_len)` on page 15.
/// Compute the base 2^b representation of X.
///
/// Input: Byte string `X` of length at least ceil(`out_len·b/8`), integer `b`, output length `out_len`. <br>
/// Output: Array of `out_len` integers in the range `[0, . . . , 2^b − 1]`.
pub(crate) fn base_2b(x: &[u8], b: u32, out_len: usize) -> Vec<u64> {
    assert!(x.len() >= out_len * b as usize / 8);
    let mut baseb = vec![0u64; out_len];
    // 1: in ← 0
    let mut inn = 0;
    // 2: bits ← 0
    let mut bits = 0;
    // 3: total ← 0
    let mut total = 0;
    // 4:
    // 5: for out from 0 to out_len − 1 do
    for out in 0..out_len {
        // 6:    while bits < b do
        while bits < b {
            // 7:      total ← (total ≪ 8) + X[in]
            total = (total << 8) + x[inn] as u64;
            // 8:      in ← in + 1
            inn += 1;
            // 9:      bits ← bits + 8
            bits += 8;
            // 10:   end while
        }
        // 11:   bits ← bits − b
        bits -= b;
        // 12:   baseb[out] ← (total ≫ bits) mod 2^b
        baseb[out] = (total >> bits) & (2u64.pow(b) - 1);
        // 13: end for
    }
    // 14: return baseb
    baseb
}

#[must_use]
pub(crate) fn shake256<N: ArrayLength>(input: &[&[u8]]) -> GenericArray<u8, N> {
    let mut hasher = Shake256::default();
    input.iter().for_each(|item| hasher.update(item));
    let mut reader = hasher.finalize_xof();
    let mut result = GenericArray::default();
    reader.read(&mut result);
    result
}

pub(crate) fn f<N: ArrayLength>(pk_seed: &[u8], adrs: &ADRS, tmp: &GenericArray<u8, N>) -> GenericArray<u8, N> {
    shake256(&[&pk_seed, &adrs.to_bytes(), tmp]).into()
}


/// Algorithm 4: `chain(X, i, s, PK.seed, ADRS)` on page 17.
/// Chaining function used in WOTS+. The chain function takes as input an n-byte string `X` and integers `s` and `i`
/// and returns the result of iterating a hash function `F` on the input `s` times, starting from an index of `i`.
/// The chain function also requires as input PK.seed, which is part of the SLH-DSA public key, and an address `ADRS`.
/// The type in `ADRS` must be set to `WOTS_HASH`, and the layer address, tree address, key pair address, and chain
/// address must be set to the address of the chain being computed. The chain function updates the hash address in
/// `ADRS` with each iteration to specify the current position in the chain prior to ADRS’s use in `F`.
///
/// Input: Input string `X`, start index `i`, number of steps `s`, public seed `PK.seed`, address `ADRS`. <br>
/// Output: Value of `F` iterated `s` times on `X`.
pub(crate) fn chain<N: ArrayLength>(
    context: &Context, cap_x: GenericArray<u8, N>, i: usize, s: usize, pk_seed: &[u8], adrs: &ADRS,
) -> Option<GenericArray<u8, N>> {
    let mut adrs = adrs.clone();
    // 1: if (i + s) ≥ w then
    if (i + s) >= context.w {
        // 2:   return NULL
        return None;
        // 3: end if
    }
    // 4:
    // 5: tmp ← X
    let mut tmp = cap_x;
    // 6:
    // 7: for j from i to i + s − 1 do
    for j in i..(i + s) {
        // 8:    ADRS.setHashAddress(j)
        adrs.set_hash_address(j.try_into().expect("usize->u32 fails"));
        // 9:    tmp ← F(PK.seed, ADRS, tmp)
        tmp = f(&pk_seed, &adrs, &tmp)
        // 10: end for
    }
    // 11: return tmp
    Some(tmp)
}


pub(crate) fn prf<N: ArrayLength>(pk_seed: &[u8], sk_seed: &[u8], adrs: &ADRS) -> GenericArray<u8, N> {
    shake256(&[&pk_seed, &sk_seed, &adrs.to_bytes()])
}


pub(crate) fn tlen<LEN: ArrayLength, N: ArrayLength>(
    _context: &Context, pk_seed: &[u8], adrs: &ADRS, ml: &GenericArray<GenericArray<u8, N>, LEN>,
) -> GenericArray<u8, N> {
    // assert!(ml
    //     .iter()
    //     .all(|item| item.as_ref().len() == context.len1));
    let mut hasher = Shake256::default();
    hasher.update(pk_seed);
    hasher.update(&adrs.to_bytes());
    ml.iter()
        .for_each(|item| hasher.update(&item.as_ref()));
    let mut reader = hasher.finalize_xof();
    let mut result = GenericArray::default();
    reader.read(&mut result);
    result
}


/// Algorithm 5: `wots_PKgen(SK.seed, PK.seed, ADRS)` on page 18.
/// Generate a WOTS+ public key. The `wots_PKgen` function generates WOTS+ public keys. It takes as input `SK.seed`
/// and `PK.seed` from the SLH-DSA private key and an address. The type in the address `ADRS` must be set to
/// `WOTS_HASH`, and the layer address, tree address, and key pair address must encode the address of the `WOTS+`
/// public key to be generated.
///
/// Input: Secret seed `SK.seed`, public seed `PK.seed`, address `ADRS`. <br>
/// Output: WOTS+ public key `pk`.
pub(crate) fn wots_pkgen<LEN: ArrayLength, N: ArrayLength>(
    context: &Context, sk_seed: &[u8], pk_seed: &[u8], adrs: &mut ADRS,
) -> GenericArray<u8, N> {
    let mut tmp: GenericArray<GenericArray<u8, N>, LEN> = GenericArray::default();

    // 1: skADRS ← ADRS    ▷ Copy address to create key generation key address
    let mut sk_adrs = adrs.clone();

    // 2: skADRS.setTypeAndClear(WOTS_PRF)
    sk_adrs.set_type_and_clear(WOTS_PRF);

    // 3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // 4: for i from 0 to len − 1 do
    for i in 0..context.len1 {
        // 5:   skADRS.setChainAddress(i)
        sk_adrs.set_chain_address(i);

        // 6:   sk ← PRF(PK.seed, SK.seed, skADRS)    ▷ Compute secret value for chain i
        let sk = prf(pk_seed, sk_seed, &sk_adrs);

        // 7:   ADRS.setChainAddress(i)
        adrs.set_chain_address(i);

        // 8:   tmp[i] ← chain(sk, 0, w − 1, PK.seed, ADRS)    ▷ Compute public value for chain i
        tmp[i] = chain(context, sk, 0, context.w - 1, pk_seed, adrs).expect("chain broek!");

        // 9: end for
    }
    // 10: wotspkADRS ← ADRS    ▷ Copy address to create WOTS+ public key address
    let mut wotspk_adrs = adrs.clone();

    // 11: wotspkADRS.setTypeAndClear(WOTS_PK)
    wotspk_adrs.set_type_and_clear(WOTS_PK);

    // 12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // 13: pk ← Tlen (PK.seed, wotspkADRS,tmp)    ▷ Compress public key
    let pk = tlen(context, pk_seed, &wotspk_adrs, &tmp);

    // 14: return pk
    pk
}


/// Algorithm 6: `wots_sign(M, SK.seed, PK.seed, ADRS)` on page 19.
/// Generate a WOTS+ signature on an n-byte message.
///
/// Input: Message `M`, secret seed `SK.seed`, public seed `PK.seed`, address `ADRS`. <br>
/// Output: WOTS+ signature sig.
pub(crate) fn wots_sign<N: ArrayLength, LEN: ArrayLength>(context: &Context, m: &[u8], sk_seed: &[u8], pk_seed: &[u8], adrs: ADRS) -> WotsSig<N, LEN> {
    let mut adrs = adrs;
    let mut sig: WotsSig<N, LEN> = WotsSig::default();

    // 1: csum ← 0
    let mut csum = 0u64;

    // 2:
    // 3: msg ← base_2b(M, lgw, len1)    ▷ Convert message to base w
    let mut msg = base_2b(m, context.lgw, context.len1);

    // 4:
    // 5: for i from 0 to len1 − 1 do    ▷ Compute checksum
    for i in 0..context.len1 {

        // 6:   csum ← csum + w − 1 − msg[i]
        csum += context.w as u64 - 1 - msg[i];

        // 7: end for
    }
    // 8:
    // 9: csum ← csum ≪ ((8 − ((len2·lgw) mod 8)) mod 8)    ▷ For lgw = 4 left shift by 4
    csum = csum << ((8 - ((context.len2 * context.lgw as usize) % 8)) % 8);

    // 10: msg ← msg ∥ base_2^b(toByte(csum, ceil(len2·lgw/8)), lgw, len2)    ▷ Convert csum to base w
    msg.extend(&base_2b(&to_byte(csum, (context.len2 * context.lgw as usize).div_ceil(8)), context.lgw, context.len2));

    // 11:
    // 12: skADRS ← ADRS
    let mut sk_addrs = adrs.clone();

    // 13: skADRS.setTypeAndClear(WOTS_PRF)
    sk_addrs.set_type_and_clear(WOTS_PRF);

    // 14: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    sk_addrs.set_key_pair_address(adrs.get_key_pair_address());

    // 15: for i from 0 to len − 1 do
    for i in 0..context.len {

        // 16:   skADRS.setChainAddress(i)
        sk_addrs.set_chain_address(i);

        // 17:   sk ← PRF(PK.seed, SK.seed, skADRS)    ▷ Compute secret value for chain i
        let sk = prf(pk_seed, sk_seed, &sk_addrs);

        // 18:   ADRS.setChainAddress(i)
        adrs.set_chain_address(i);

        // 19:   sig[i] ← chain(sk, 0, msg[i], PK.seed, ADRS)    ▷ Compute signature value for chain i
        sig.data[i] = chain(context, sk, 0, msg[i] as usize, pk_seed, &adrs).unwrap();

        // 20: end for
    }
    // 21: return sig
    sig
}

/// Algorithm 7: `wots_PKFromSig(sig, M, PK.seed, ADRS)` on page 20.
/// Compute a WOTS+ public key from a message and its signature.
///
/// Input: WOTS+ signature `sig`, message `M`, public seed `PK.seed`, address `ADRS`. <br>
/// Output: WOTS+ public key `pksig` derived from `sig`.
const _A7: u32 = 0;
// 1: csum ← 0
// 2:
// 3: msg ← base_2b (M, lgw , len1 )    ▷ Convert message to base w
// 4:
// 5: for i from 0 to len1 − 1 do    ▷ Compute checksum
// 6:   csum ← csum + w − 1 − msg[i]
// 7: end for
// 8:
// 9: csum ← csum ≪ ((8 − ((len2·lgw) mod 8)) mod 8)    ▷ For lgw = 4 left shift by 4
// 10: msg ← msg ∥ base_2^b(toByte(csum, ceil(len2·lgw/8)), lgw, len2)    ▷ Convert csum to base w
// 11: for i from 0 to len − 1 do
// 12:   ADRS.setChainAddress(i)
// 13:   tmp[i] ← chain(sig[i], msg[i], w − 1 − msg[i], PK.seed, ADRS)
// 14: end for
// 15: wotspkADRS ← ADRS
// 16: wotspkADRS.setTypeAndClear(WOTS_PK)
// 17: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
// 18: pksig ← Tlen (PK.seed, wotspkADRS, tmp)
// 19: return pksig


/// Algorithm 8: `xmss_node(SK.seed, i, z, PK.seed, ADRS)` on page 22.
/// Compute the root of a Merkle subtree of WOTS+ public keys.
///
/// Input: Secret seed `SK.seed`, target node index `i`, target node height `z`, public seed `PK.seed`,
/// `address ADRS`. <br>
/// Output: n-byte root `node`.
const _A8: u32 = 0;
// 1: if z > h′ or i ≥ 2^{h −z} then
// 2:   return NULL
// 3: end if
// 4: if z = 0 then
// 5:    ADRS.setTypeAndClear(WOTS_HASH)
// 6:    ADRS.setKeyPairAddress(i)
// 7:    node ← wots_PKgen(SK.seed, PK.seed, ADRS)
// 8: else
// 9:    lnode ← xmss_node(SK.seed, 2i, z − 1, PK.seed, ADRS)
// 10:   rnode ← xmss_node(SK.seed, 2i + 1, z − 1, PK.seed, ADRS)
// 11:   ADRS.setTypeAndClear(TREE)
// 12:   ADRS.setTreeHeight(z)
// 13:   ADRS.setTreeIndex(i)
// 14:   node ← H(PK.seed, ADRS, lnode ∥ rnode)
// 15: end if
// 16: return node


/// Algorithm 9: `xmss_sign(M, SK.seed, idx, PK.seed, ADRS)` on page 23.
/// Generate an XMSS signature.
///
/// Input: n-byte message `M`, secret seed `SK.seed`, index `idx`, public seed `PK.seed`, address `ADRS`. <br>
/// Output: XMSS signature SIGXMSS = (sig ∥ AUTH).
const _A9: u32 = 0;
//
// 1: for j from 0 to h′-1 do    ▷ Build authentication path
// 2:   k ← idx/2 xor 1
// 3:   AUTH[j] ← xmss_node(SK.seed, k, j, PK.seed, ADRS)
// 4: end for
// 5:
// 6: ADRS.setTypeAndClear(WOTS_HASH)
// 7: ADRS.setKeyPairAddress(idx)
// 8: sig ← wots_sign(M, SK.seed, PK.seed, ADRS)
// 9: SIG_XMSS ← sig ∥ AUTH
// 10: return SIG_XMSS


/// Algorithm 10: `xmss_PKFromSig(idx, SIG_XMSS, M, PK.seed, ADRS)`
/// Compute an XMSS public key from an XMSS signature.
///
/// Input: Index `idx`, XMSS signature `SIG_XMSS = (sig ∥ AUTH)`, n-byte message `M`, public seed `PK.seed`,
/// address `ADRS`. <br>
/// Output: n-byte root value `node[0]`.
const _A10: u32 = 0;
// 1: ADRS.setTypeAndClear(WOTS_HASH)    ▷ Compute WOTS+ pk from WOTS+ sig
// 2: ADRS.setKeyPairAddress(idx)
// 3: sig ← SIG_XMSS .getWOTSSig()    ▷ SIG_XMSS [0 : len · n]
// 4: AUTH ← SIG_XMSS .getXMSSAUTH()    ▷ SIG_XMSS [len · n : (len + h′) · n]
// 5: node[0] ← wots_PKFromSig(sig, M, PK.seed, ADRS)
// 6:
// 7: ADRS.setTypeAndClear(TREE)    ▷ Compute root from WOTS+ pk and AUTH
// 8: ADRS.setTreeIndex(idx)
// 9: for k from 0 to h′ − 1 do
// 10:   ADRS.setTreeHeight(k + 1)
// 11:   if idx/2^k is even then
// 12:     ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
// 13:     node[1] ← H(PK.seed, ADRS, node[0] ∥ AUTH[k])
// 14:   else
// 15:     ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
// 16:     node[1] ← H(PK.seed, ADRS, AUTH[k] ∥ node[0])
// 17:   end if
// 18:   node[0] ← node[1]
// 19: end for
// 20: return node[0]


/// Algorithm 11: `ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf)` on page 27.
/// Generate a hypertree signature.
///
/// Input: Message `M`, private seed `SK.seed`, public seed `PK.seed`, tree index `idx_tree`, leaf
/// index `idx_leaf`. <br>
/// Output: HT signature SIG_HT.
const _A11: u32 = 0;
// 1: ADRS ← toByte(0, 32)
// 2:
// 3: ADRS.setTreeAddress(idxtree)
// 4: SIG_tmp ← xmss_sign(M, SK.seed, idxleaf, PK.seed, ADRS)
// 5: SIG_HT ← SIG_tmp
// 6: root ← xmss_PKFromSig(idx_leaf, SIG_tmp, M, PK.seed, ADRS)
// 7: for j from 1 to d − 1 do
// 8:    idx_leaf ← idx_tree mod 2^{h′}    ▷ h′ least significant bits of idx_tree
// 9:    idx_tree ← idx_tree ≫ h′    ▷ Remove least significant h′ bits from idx_tree
// 10:   ADRS.setLayerAddress(j)
// 11:   ADRS.setTreeAddress(idx_tree)
// 12:   SIG_tmp ← xmss_sign(root, SK.seed, idx_leaf, PK.seed, ADRS)
// 13:   SIG_HT ← SIG_HT ∥ SIG_tmp
// 14:   if j < d − 1 then
// 15:     root ← xmss_PKFromSig(idx_leaf, SIG_tmp, root, PK.seed, ADRS)
// 16:   end if
// 17: end for
// 18: return SIGHT


/// Algorithm 12: `ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)` on page 28.
/// Verify a hypertree signature.
///
/// Input: Message `M`, signature `SIG_HT`, public seed `PK.seed`, tree index `idx_tree`, leaf index `idx_leaf`,
/// HT public key `PK.root`. <br>
/// Output: Boolean.
const _A12: u32 = 0;
// 1: ADRS ← toByte(0, 32)
// 2:
// 3: ADRS.setTreeAddress(idx_tree)
// 4: SIG_tmp ← SIG_HT.getXMSSSignature(0)    ▷ SIG_HT [0 : (h′ + len) · n]
// 5: node ← xmss_PKFromSig(idx_leaf, SIG_tmp, M, PK.seed, ADRS)
// 6: for j from 1 to d − 1 do
// 7:    idx_leaf ← idx_tree mod 2^{h′}    ▷ h′ least significant bits of idx_tree
// 8:    idx_tree ← idx_tree ≫ h′    ▷ Remove least significant h′ bits from idx_tree
// 9:    ADRS.setLayerAddress(j)
// 10:   ADRS.setTreeAddress(idx_tree)
// 11:   SIG_tmp ← SIG_HT.getXMSSSignature(j)     ▷ SIGHT [ j · (h′ + len) · n : ( j + 1)(h′ + len) · n]
// 12:   node ← xmss_PKFromSig(idx_leaf, SIG_tmp, node, PK.seed, ADRS)
// 13: end for
// 14: if node = PK.root then
// 15:   return true
// 16: else
// 17:   return false
// 18: end if


/// Algorithm 13: `fors_SKgen(SK.seed, PK.seed, ADRS, idx)` on page 29.
/// Generate a FORS private-key value.
///
/// Input: Secret seed `SK.seed`, public seed `PK.seed`, address `ADRS`, secret key index `idx`. <br>
/// Output: n-byte FORS private-key value.
const _A13: u32 = 0;
// 1: skADRS ← ADRS    ▷ Copy address to create key generation address
// 2: skADRS.setTypeAndClear(FORS_PRF)
// 3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
// 4: skADRS.setTreeIndex(idx)
// 5: return PRF(PK.seed, SK.seed, skADRS)


/// Algorithm 14: `fors_node(SK.seed, i, z, PK.seed, ADRS)` on page 30.
/// Compute the root of a Merkle subtree of FORS public values.
///
/// Input: Secret seed `SK.seed`, target node index `i`, target node height `z`, public seed `PK.seed`,
/// address `ADRS`. <br>
/// Output: n-byte root node.
const _A14: u32 = 0;
// 1: if z > a or i ≥ k · 2(a−z) then
// 2:   return NULL
// 3: end if
// 4: if z = 0 then
// 5:    sk ← fors_SKgen(SK.seed, PK.seed, ADRS, i)
// 6:    ADRS.setTreeHeight(0)
// 7:    ADRS.setTreeIndex(i)
// 8:    node ← F(PK.seed, ADRS, sk)
// 9:  else
// 10:   lnode ← fors_node(SK.seed, 2i, z − 1, PK.seed, ADRS)
// 11:   rnode ← fors_node(SK.seed, 2i + 1, z − 1, PK.seed, ADRS)
// 12:   ADRS.setTreeHeight(z)
// 13:   ADRS.setTreeIndex(i)
// 14:   node ← H(PK.seed, ADRS, lnode ∥ rnode)
// 15: end if
// 16: return node


/// Algorithm 15: `fors_sign(md, SK.seed, PK.seed, ADRS)`
/// Generate a FORS signature.
///
/// Input: Message digest `md`, secret seed `SK.seed`, address `ADRS`, public seed `PK.seed`. <br>
/// Output: FORS signature `SIG_FORS`.
const _A15: u32 = 0;
// 1: SIG_FORS = NULL    ▷ Initialize SIG_FORS as a zero-length byte string
// 2: indices ← base_2^b(md, a, k)
// 3: for i from 0 to k − 1 do    ▷ Compute signature elements
// 4:    SIG_FORS ← SIG_FORS ∥ fors_SKgen(SK.seed, PK.seed, ADRS, i · 2a + indices[i])
// 5:
// 6:    for j from 0 to a − 1 do    ▷ Compute auth path
// 7:      s ← indices[i]/2^j xor 1
// 8:      AUTH[j] ← fors_node(SK.seed, i · 2^{a−j} + s, j, PK.seed, ADRS)
// 9:    end for
// 10:   SIG_FORS ← SIG_FORS ∥ AUTH
// 11: end for
// 12: return SIG_FORS


/// Algorithm 16: `fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)` on page 32.
/// Compute a FORS public key from a FORS signature.
///
/// Input: FORS signature `SIG_FORS`, message digest `md`, public seed `PK.seed`, address `ADRS`. <br>
/// Output: FORS public key.
const _A16: u32 = 0;
// 1: indices ← base_2^b(md, a, k)
// 2: for i from 0 to k − 1 do
// 3:   sk ← SIG_FORS.getSK(i)    ▷ SIG_FORS [i · (a + 1) · n : (i · (a + 1) + 1) · n]
// 4:   ADRS.setTreeHeight(0)    ▷ Compute leaf
// 5:   ADRS.setTreeIndex(i · 2^a + indices[i])
// 6:   node[0] ← F(PK.seed, ADRS, sk)
// 7:
// 8: auth ← SIGFORS .getAUTH(i)    ▷ SIGFORS [(i · (a + 1) + 1) · n : (i + 1) · (a + 1) · n]
// 9: for j from 0 to a − 1 do    ▷ Compute root from leaf and AUTH
// 10:  ADRS.setTreeHeight(j + 1)
// 11:  if indices[i]/2^jj is even then
// 12:    ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
// 13:    node[1] ← H(PK.seed, ADRS, node[0] ∥ auth[j])
// 14:  else
// 15:    ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
// 16:    node[1] ← H(PK.seed, ADRS, auth[j] ∥ node[0])
// 17:  end if
// 18: node[0] ← node[1]
// 19: end for
// 20: root[i] ← node[0]
// 21: end for
// 22: forspkADRS ← ADRS    ▷ Compute the FORS public key from the Merkle tree roots
// 23: forspkADRS.setTypeAndClear(FORS_ROOTS)
// 24: forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
// 25: pk ← Tk(PK.seed, forspkADRS, root)
// 26: return pk;


/// Algorithm 17: `slh_keygen()` on page 34.
/// Generate an SLH-DSA key pair.
///
/// Input: (none) <br>
/// Output: SLH-DSA key pair `(SK, PK)`.
const _A17: u32 = 0;
// 1: SK.seed ←$ B^n    ▷ Set SK.seed, SK.prf, and PK.seed to random n-byte
// 2: SK.prf ←$ B^n    ▷ strings using an approved random bit generator
// 3: PK.seed ←$ B^n
// 4:
// 5: ADRS ← toByte(0, 32)    ▷ Generate the public key for the top-level XMSS tree
// 6: ADRS.setLayerAddress(d − 1)
// 7: PK.root ← xmss_node(SK.seed, 0, h′, PK.seed, ADRS)
// 8:
// 9: return ( (SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root) )


/// Algorithm 18: `slh_sign(M, SK)` on page 35.
/// Generate an SLH-DSA signature.
///
/// Input: Message `M`, private key `SK = (SK.seed, SK.prf, PK.seed, PK.root)`. <br>
/// Output: SLH-DSA signature `SIG`.
const _A18: u32 = 0;
// 1: ADRS ← toByte(0, 32)
// 2:
// 3: opt_rand ← PK.seed    ▷ Set opt_rand to either PK.seed
// 4: if (RANDOMIZE) then    ▷ or to a random n-byte string
// 5:   opt_rand ←$ Bn
// 6: end if
// 7: R ← PRF_msg(SK.prf, opt_rand, M)    ▷ Generate randomizer
// 8: SIG ← R
// 9:
// 10: digest ← H_msg(R, PK.seed, PK.root, M)    ▷ Compute message digest
// 11: md ← digest[0 : ceil(k·a/8)]    ▷ first ceil(k·a/8) bytes
// 12: tmp_idx_tree ← digest[ceil(k·a/8) : ceil(k·a/8) + ceil((h-h/d)/8)]    ▷ next ceil((h-h/d)/8) bytes
// 13: tmp_idx_leaf ← digest[ceil(k·a/8) + ceil((h-h/d)/8) : ceil(k·a/8) + ceil((h-h/d)/8) + ceil(h/8d)]    ▷ next ceil(h/8d) bytes
// 14:
// 15: idx_tree ← toInt(tmp_idx_tree, ceil((h-h/d)/8)) mod 2^{h−h/d}
// 16: idx_leaf ← toInt(tmp_idx_leaf, ceil(h/8d) mod 2^{h/d}
// 17:
// 18: ADRS.setTreeAddress(idx_tree)
// 19: ADRS.setTypeAndClear(FORS_TREE)
// 20: ADRS.setKeyPairAddress(idxleaf)
// 21: SIG_FORS ← fors_sign(md, SK.seed, PK.seed, ADRS)
// 22: SIG ← SIG ∥ SIG_FORS
// 23:
// 24: PK_FORS ← fors_pkFromSig(SIG_FORS , md, PK.seed, ADRS)    ▷ Get FORS key
// 25:
// 26: SIG_HT ← ht_sign(PK_FORS , SK.seed, PK.seed, idx_tree, idx_leaf)
// 27: SIG ← SIG ∥ SIG_HT
// 28: return SIG


/// Algorithm 19: `slh_verify(M, SIG, PK)`
/// Verify an SLH-DSA signature.
///
/// Input: Message `M`, signature `SIG`, public key `PK = (PK.seed, PK.root)`. <br>
/// Output: Boolean.
const _A19: u32 = 0;
// 1: if |SIG| != (1 + k(1 + a) + h + d · len) · n then
// 2:   return false
// 3: end if
// 4: ADRS ← toByte(0, 32)
// 5: R ← SIG.getR()    ▷ SIG[0 : n]
// 6: SIG_FORS ← SIG.getSIG_FORS()    ▷ SIG[n : (1 + k(1 + a)) · n]
// 7: SIG_HT ← SIG.getSIG_HT()    ▷ SIG[(1 + k(1 + a)) · n : (1 + k(1 + a) + h + d · len) · n]
// 8:
// 9: digest ← Hmsg(R, PK.seed, PK.root, M)    ▷ Compute message digest
// 10: md ← digest[0 : ceil(k·a/8)]    ▷ first ceil(k·a/8) bytes
// 11: tmp_idx_tree ← digest[ceil(k·a/8) : ceil(k·a/8) + ceil((h - h/d)/8)]     ▷ next ceil((h - h/d)/8) bytes
// 12: tmp_idx_leaf ← digest[ceil(k·a/8) + ceil((h - h/d)/8) : ceil(k·a/8) + ceil((h - h/d)/8) + ceil(h/8d)]  ▷ next ceil(h/8d) bytes
// 13:
// 14: idx_tree ← toInt(tmp_idx_tree, ceil((h - h/d)/8)) mod 2^{h−h/d}
// 15: idx_leaf ← toInt(tmp_idx_leaf, ceil(h/8d) mod 2^{h/d}
// 16:
// 17: ADRS.setTreeAddress(idx_tree)    ▷ Compute FORS public key
// 18: ADRS.setTypeAndClear(FORS_TREE)
// 19: ADRS.setKeyPairAddress(idx_leaf)
// 20:
// 21: PK_FORS ← fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)
// 22:
// 23: return ht_verify(PK_FORS, SIG_HT, PK.seed, idx_tree , idx_leaf, PK.root)
