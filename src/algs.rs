use crate::hashers::Hashers;
use crate::types::{
    Adrs, ForsPk, ForsSig, HtSig, SlhDsaSig, SlhPrivateKey, SlhPublicKey, WotsPk, WotsSig, XmssSig,
};
use crate::types::{FORS_PRF, FORS_ROOTS, FORS_TREE, TREE, WOTS_HASH, WOTS_PK, WOTS_PRF};
use generic_array::{ArrayLength, GenericArray};
use rand_core::CryptoRngCore;


/// Algorithm 1: `toInt(X, n)` on page 14.
/// Convert a byte string to an integer.
///
/// Input: n-byte string `X`, string length `n`. <br>
/// Output: Integer value of `X`.
pub(crate) fn to_int(x: &[u8], n: usize) -> u64 {
    debug_assert_eq!(x.len(), n);

    // 1: total ← 0
    let mut total = 0_u64;

    // 2:
    // 3: for i from 0 to n − 1 do
    for item in x.iter().take(n) {
        //
        // 4:   total ← 256 · total + X[i]
        total = (total << 8) + u64::from(*item);

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
pub(crate) fn to_byte(x: u16, n: usize) -> [u8; ((crate::LEN2 * crate::LGW + 7) / 8) as usize] {
    let mut s = [0u8; ((crate::LEN2 * crate::LGW + 7) / 8) as usize]; // Size fixed across all profiles (2)
    debug_assert_eq!(n, ((crate::LEN2 * crate::LGW + 7) / 8) as usize); // just in case life changes

    // 1: total ← x
    let mut total = x;

    // 2:
    // 3: for i from 0 to n − 1 do
    for i in 0..n {
        //
        // 4:   S[n − 1 − i] ← total mod 256    ▷ Least significant 8 bits of total
        s[n - 1 - i] = total.to_le_bytes()[0];

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
/// Input: Byte string `X` of length at least ceil(out_len·b/8), integer `b`, output length `out_len`. <br>
/// Output: Array of `out_len` integers in the range `[0, . . . , 2^b − 1]`.
pub(crate) fn base_2b(x: &[u8], b: u32, out_len: u32, baseb: &mut [u32]) {
    debug_assert!(x.len() >= (out_len * b / 8) as usize);
    debug_assert!(b < 16);
    debug_assert_eq!(out_len as usize, baseb.len());

    // 1: in ← 0
    let mut inn = 0;

    // 2: bits ← 0
    let mut bits = 0;

    // 3: total ← 0
    let mut total = 0;

    // 4:
    // 5: for out from 0 to out_len − 1 do
    for item in baseb.iter_mut().take(out_len as usize) {
        //
        // 6:    while bits < b do
        while bits < b {
            //
            // 7:      total ← (total ≪ 8) + X[in]
            total = (total << 8) + u32::from(x[inn]);

            // 8:      in ← in + 1
            inn += 1;

            // 9:      bits ← bits + 8
            bits += 8;

            // 10:   end while
        }

        // 11:   bits ← bits − b
        bits -= b;

        // 12:   baseb[out] ← (total ≫ bits) mod 2^b
        *item = (total >> bits) & (u32::MAX >> (32 - b));

        assert!(*item < u32::MAX);
        // 13: end for
    }

    // 14: return baseb  (mutable parameter)
}


/// Algorithm 4: `chain(X, i, s, PK.seed, ADRS)` on page 17.
/// Chaining function used in WOTS+. The chain function takes as input an n-byte string `X` and integers `s` and `i`
/// and returns the result of iterating the hash function `F` on the input `s` times, starting from an index of `i`.
/// The chain function also requires as input PK.seed, which is part of the SLH-DSA public key, and an address `ADRS`.
/// The type in `ADRS` must be set to `WOTS_HASH`, and the layer address, tree address, key pair address, and chain
/// address must be set to the address of the chain being computed. The chain function updates the hash address in
/// `ADRS` with each iteration to specify the current position in the chain prior to ADRS’s use in `F`.
///
/// Input: Input string `X`, start index `i`, number of steps `s`, public seed `PK.seed`, address `ADRS`. <br>
/// Output: Value of `F` iterated `s` times on `X`.
pub(crate) fn chain<K: ArrayLength, LEN: ArrayLength, M: ArrayLength, N: ArrayLength>(
    hashers: &Hashers<K, LEN, M, N>, cap_x: GenericArray<u8, N>, i: u32, s: u32,
    pk_seed: &[u8], adrs: &Adrs,
) -> Option<GenericArray<u8, N>> {
    debug_assert!(i + s < u32::MAX);
    let mut adrs = adrs.clone();

    // 1: if (i + s) ≥ w then
    if (i + s) >= crate::W {
        //
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
        //
        // 8:    ADRS.setHashAddress(j)
        adrs.set_hash_address(j);

        // 9:    tmp ← F(PK.seed, ADRS, tmp)
        tmp = (hashers.f)(pk_seed, &adrs, &tmp);

        // 10: end for
    }

    // 11: return tmp
    Some(tmp)
}


/// Algorithm 5: `wots_PKgen(SK.seed, PK.seed, ADRS)` on page 18.
/// Generate a WOTS+ public key. The `wots_PKgen` function generates WOTS+ public keys. It takes as input `SK.seed`
/// and `PK.seed` from the SLH-DSA private key and an address. The type in the address `ADRS` must be set to
/// `WOTS_HASH`, and the layer address, tree address, and key pair address must encode the address of the `WOTS+`
/// public key to be generated.
///
/// Input: Secret seed `SK.seed`, public seed `PK.seed`, address `ADRS`. <br>
/// Output: WOTS+ public key `pk`.
#[allow(clippy::similar_names)]
pub(crate) fn wots_pkgen<K: ArrayLength, LEN: ArrayLength, M: ArrayLength, N: ArrayLength>(
    hashers: &Hashers<K, LEN, M, N>, sk_seed: &[u8], pk_seed: &[u8], adrs: &Adrs,
) -> Result<WotsPk<N>, &'static str> {
    let mut adrs = adrs.clone();
    let mut tmp: GenericArray<GenericArray<u8, N>, LEN> = GenericArray::default();

    // 1: skADRS ← ADRS    ▷ Copy address to create key generation key address
    let mut sk_adrs = adrs.clone();

    // 2: skADRS.setTypeAndClear(WOTS_PRF)
    sk_adrs.set_type_and_clear(WOTS_PRF);

    // 3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // 4: for i from 0 to len − 1 do
    for i in 0..LEN::to_u32() {
        //
        // 5:   skADRS.setChainAddress(i)
        sk_adrs.set_chain_address(i);

        // 6:   sk ← PRF(PK.seed, SK.seed, skADRS)    ▷ Compute secret value for chain i
        let sk = (hashers.prf)(pk_seed, sk_seed, &sk_adrs);

        // 7:   ADRS.setChainAddress(i)
        adrs.set_chain_address(i);

        // 8:   tmp[i] ← chain(sk, 0, w − 1, PK.seed, ADRS)    ▷ Compute public value for chain i
        tmp[i as usize] =
            chain(hashers, sk, 0, crate::W - 1, pk_seed, &adrs).ok_or("chain broke")?;

        // 9: end for
    }

    // 10: wotspkADRS ← ADRS    ▷ Copy address to create WOTS+ public key address
    let mut wotspk_adrs = adrs.clone();

    // 11: wotspkADRS.setTypeAndClear(WOTS_PK)
    wotspk_adrs.set_type_and_clear(WOTS_PK);

    // 12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // 13: pk ← Tlen (PK.seed, wotspkADRS, tmp)    ▷ Compress public key
    let pk = (hashers.t_l)(pk_seed, &wotspk_adrs, &tmp);

    // 14: return pk
    Ok(WotsPk(pk))
}


/// Algorithm 6: `wots_sign(M, SK.seed, PK.seed, ADRS)` on page 19.
/// Generate a WOTS+ signature on an n-byte message.
///
/// Input: Message `M`, secret seed `SK.seed`, public seed `PK.seed`, address `ADRS`. <br>
/// Output: WOTS+ signature sig.
#[allow(clippy::similar_names)]
pub(crate) fn wots_sign<K: ArrayLength, LEN: ArrayLength, M: ArrayLength, N: ArrayLength>(
    hashers: &Hashers<K, LEN, M, N>, m: &[u8], sk_seed: &[u8], pk_seed: &[u8], adrs: &Adrs,
) -> WotsSig<LEN, N> {
    let mut adrs = adrs.clone();
    let mut sig: WotsSig<LEN, N> = WotsSig::default();

    // 1: csum ← 0
    let mut csum = 0_u32;

    // 2:
    // 3: msg ← base_2b(M, lgw, len1)    ▷ Convert message to base w
    let mut msg = GenericArray::<u32, LEN>::default(); // note: 3 entries left over, used step 10
    base_2b(m, crate::LGW, 2 * N::to_u32(), &mut msg[0..(2 * N::to_usize())]);

    // 4:
    // 5: for i from 0 to len1 − 1 do    ▷ Compute checksum
    for item in msg.iter().take(2 * N::to_usize()) {
        //
        // 6:   csum ← csum + w − 1 − msg[i]
        csum += crate::W - 1 - *item;

        // 7: end for
    }

    // 8:
    // 9: csum ← csum ≪ ((8 − ((len2·lgw) mod 8)) mod 8)    ▷ For lgw = 4 left shift by 4
    let len2 = 3_u32; //
    csum <<= (8 - ((len2 * crate::LGW) & 0x07)) & 0x07;

    // 10: msg ← msg ∥ base_2^b(toByte(csum, ceil(len2·lgw/8)), lgw, len2)    ▷ Convert csum to base w
    base_2b(
        &to_byte(csum as u16, ((len2 * crate::LGW) as usize).div_ceil(8)),
        crate::LGW,
        len2,
        &mut msg[(2 * N::to_usize())..],
    );

    // 11:
    // 12: skADRS ← ADRS
    let mut sk_addrs = adrs.clone();

    // 13: skADRS.setTypeAndClear(WOTS_PRF)
    sk_addrs.set_type_and_clear(WOTS_PRF);

    // 14: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    sk_addrs.set_key_pair_address(adrs.get_key_pair_address());

    // 15: for i from 0 to len − 1 do
    let len = 2 * N::to_usize() + 3;
    //#[allow(clippy::cast_possible_truncation)] // step 19
    for (item, i) in msg.iter().zip(0u32..).take(len) {
        //
        // 16:   skADRS.setChainAddress(i)
        sk_addrs.set_chain_address(i);

        // 17:   sk ← PRF(PK.seed, SK.seed, skADRS)    ▷ Compute secret value for chain i
        let sk = (hashers.prf)(pk_seed, sk_seed, &sk_addrs);

        // 18:   ADRS.setChainAddress(i)
        adrs.set_chain_address(i);

        // 19:   sig[i] ← chain(sk, 0, msg[i], PK.seed, ADRS)    ▷ Compute signature value for chain i
        sig.data[i as usize] = chain(hashers, sk, 0, *item, pk_seed, &adrs).unwrap();

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
pub(crate) fn wots_pk_from_sig<K: ArrayLength, LEN: ArrayLength, M: ArrayLength, N: ArrayLength>(
    hashers: &Hashers<K, LEN, M, N>, sig: &WotsSig<LEN, N>, m: &[u8], pk_seed: &[u8], adrs: &Adrs,
) -> WotsPk<N> {
    let mut adrs = adrs.clone();
    let mut tmp: GenericArray<GenericArray<u8, N>, LEN> = GenericArray::default();

    // 1: csum ← 0
    let mut csum = 0_u64;

    // 2:
    // 3: msg ← base_2b (M, lgw , len1 )    ▷ Convert message to base w
    let mut msg: GenericArray<u32, LEN> = GenericArray::default();
    base_2b(m, crate::LGW, 2 * N::to_u32(), &mut msg[0..(2 * N::to_usize())]);

    // 4:
    // 5: for i from 0 to len1 − 1 do    ▷ Compute checksum
    for item in msg.iter().take(2 * N::to_usize()) {
        //
        // 6:   csum ← csum + w − 1 − msg[i]
        csum += u64::from(crate::W) - 1 - *item as u64;

        // 7: end for
    }

    // 8:
    // 9: csum ← csum ≪ ((8 − ((len2·lgw) mod 8)) mod 8)    ▷ For lgw = 4 left shift by 4
    let len2 = 3_u32;
    csum <<= (8 - ((len2 * crate::LGW) & 0x07)) & 0x07;

    // 10: msg ← msg ∥ base_2^b(toByte(csum, ceil(len2·lgw/8)), lgw, len2)    ▷ Convert csum to base w
    base_2b(
        &to_byte(csum as u16, (len2 * crate::LGW).div_ceil(8) as usize),
        crate::LGW,
        len2,
        &mut msg[(2 * N::to_usize())..],
    );

    // 11: for i from 0 to len − 1 do
    #[allow(clippy::cast_possible_truncation)] // steps 12 and 13
    for i in 0..LEN::to_usize() {
        //
        // 12:   ADRS.setChainAddress(i)
        adrs.set_chain_address(i as u32);

        // 13:   tmp[i] ← chain(sig[i], msg[i], w − 1 − msg[i], PK.seed, ADRS)
        tmp[i] = chain::<K, LEN, M, N>(
            hashers,
            sig.data[i].clone(),
            msg[i],
            crate::W - 1 - msg[i],
            pk_seed,
            &adrs,
        )
        .expect("chain broke2!");

        // 14: end for
    }

    // 15: wotspkADRS ← ADRS
    let mut wotspk_adrs = adrs.clone();

    // 16: wotspkADRS.setTypeAndClear(WOTS_PK)
    wotspk_adrs.set_type_and_clear(WOTS_PK);

    // 17: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // 18: pksig ← Tlen (PK.seed, wotspkADRS, tmp)
    let pk = (hashers.t_l)(pk_seed, &wotspk_adrs, &tmp);

    // 19: return pksig
    WotsPk(pk)
}


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
        // 2:   return NULL
        return Err("Alg8: fail");

        // 3: end if
    }

    // 4: if z = 0 then
    let node = if z == 0 {
        //
        // 5:    ADRS.setTypeAndClear(WOTS_HASH)
        adrs.set_type_and_clear(WOTS_HASH);

        // 6:    ADRS.setKeyPairAddress(i)
        adrs.set_key_pair_address(i);

        // 7:    node ← wots_PKgen(SK.seed, PK.seed, ADRS)
        wots_pkgen::<K, LEN, M, N>(hashers, sk_seed, pk_seed, &adrs)?
            .0
            .clone() // TODO remove clone?

    // 8: else
    } else {
        //
        // 9:    lnode ← xmss_node(SK.seed, 2 * i, z − 1, PK.seed, ADRS)
        let lnode =
            xmss_node::<H, HP, K, LEN, M, N>(hashers, sk_seed, 2 * i, z - 1, pk_seed, &adrs)?;

        // 10:   rnode ← xmss_node(SK.seed, 2 * i + 1, z − 1, PK.seed, ADRS)
        let rnode =
            xmss_node::<H, HP, K, LEN, M, N>(hashers, sk_seed, 2 * i + 1, z - 1, pk_seed, &adrs)?;

        // 11:   ADRS.setTypeAndClear(TREE)
        adrs.set_type_and_clear(TREE);

        // 12:   ADRS.setTreeHeight(z)
        adrs.set_tree_height(z);

        // 13:   ADRS.setTreeIndex(i)
        adrs.set_tree_index(i);

        // 14:   node ← H(PK.seed, ADRS, lnode ∥ rnode)
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
        // 2:   k ← idx/2 ^j xor 1
        let k = (idx >> j) ^ 1;

        // 3:   AUTH[j] ← xmss_node(SK.seed, k, j, PK.seed, ADRS)
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
    sig_xmss.sig_wots = wots_sign::<K, LEN, M, N>(hashers, m, sk_seed, pk_seed, &adrs); // TODO: polish out BB!

    // 9: SIG_XMSS ← sig ∥ AUTH
    // struct constructed above

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
    let mut node_0 = wots_pk_from_sig::<K, LEN, M, N>(hashers, sig, m, pk_seed, &adrs)
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
        // 10:   ADRS.setTreeHeight(k + 1)
        adrs.set_tree_height(k + 1);

        // 11:   if idx/2^k is even then
        #[allow(clippy::if_not_else)] // Follows the algorithm as written
        let node_1 = if ((idx >> k) & 1) == 0 {
            //
            // 12:     ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
            let tmp = adrs.get_tree_index() / 2;
            adrs.set_tree_index(tmp);

            // 13:     node[1] ← H(PK.seed, ADRS, node[0] ∥ AUTH[k])
            (hashers.h)(pk_seed, &adrs, &node_0, &auth[k as usize])

            // 14:   else
        } else {
            //
            // 15:     ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
            let tmp = (adrs.get_tree_index() - 1) / 2;
            adrs.set_tree_index(tmp);

            // 16:     node[1] ← H(PK.seed, ADRS, AUTH[k] ∥ node[0])
            (hashers.h)(pk_seed, &adrs, &auth[k as usize], &node_0)

            // 17:   end if
        };

        // 18:   node[0] ← node[1]
        node_0 = node_1;

        // 19: end for
    }

    // 20: return node[0]
    node_0
}


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
        xmss_sign::<H, HP, K, LEN, M, N>(hashers, m, sk_seed, idx_leaf, pk_seed, &adrs)?;

    // 5: SIG_HT ← SIG_tmp
    let mut sig_ht = HtSig::default();
    sig_ht.xmss_sigs[0] = sig_tmp.clone();

    // 6: root ← xmss_PKFromSig(idx_leaf, SIG_tmp, M, PK.seed, ADRS)
    let mut root =
        xmss_pk_from_sig::<HP, K, LEN, M, N>(hashers, idx_leaf, &sig_tmp, m, pk_seed, &adrs);

    // 7: for j from 1 to d − 1 do
    for j in 1..D::to_u32() {
        //
        // 8:    idx_leaf ← idx_tree mod 2^{h′}    ▷ h′ least significant bits of idx_tree
        let idx_leaf = u32::try_from(idx_tree % 2u64.pow(HP::to_u32()))
            .map_err(|_| "Alg11: oversized idx leaf")?;

        // 9:    idx_tree ← idx_tree ≫ h′    ▷ Remove least significant h′ bits from idx_tree
        idx_tree >>= HP::to_u32();

        // 10:   ADRS.setLayerAddress(j)
        adrs.set_layer_address(j);

        // 11:   ADRS.setTreeAddress(idx_tree)
        adrs.set_tree_address(idx_tree);

        // 12:   SIG_tmp ← xmss_sign(root, SK.seed, idx_leaf, PK.seed, ADRS)
        sig_tmp =
            xmss_sign::<H, HP, K, LEN, M, N>(hashers, &root, sk_seed, idx_leaf, pk_seed, &adrs)?;

        // 13:   SIG_HT ← SIG_HT ∥ SIG_tmp
        sig_ht.xmss_sigs[j as usize] = sig_tmp.clone();

        // 14:   if j < d − 1 then
        if j < (D::to_u32() - 1) {
            //
            // 15:     root ← xmss_PKFromSig(idx_leaf, SIG_tmp, root, PK.seed, ADRS)
            root = xmss_pk_from_sig::<HP, K, LEN, M, N>(
                hashers, idx_leaf, &sig_tmp, &root, pk_seed, &adrs,
            );

            // 16:   end if
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
    let mut node = xmss_pk_from_sig(hashers, idx_leaf, &sig_tmp, m, pk_seed, &adrs);

    // 6: for j from 1 to d − 1 do
    for j in 1..D::to_u32() {
        //
        // 7:    idx_leaf ← idx_tree mod 2^{h′}    ▷ h′ least significant bits of idx_tree
        let idx_leaf = u32::try_from(idx_tree % 2u64.pow(HP::to_u32()));
        if idx_leaf.is_err() {
            return false;
        };
        let idx_leaf = idx_leaf.unwrap();

        // 8:    idx_tree ← idx_tree ≫ h′    ▷ Remove least significant h′ bits from idx_tree
        idx_tree >>= HP::to_u32();

        // 9:    ADRS.setLayerAddress(j)
        adrs.set_layer_address(j);

        // 10:   ADRS.setTreeAddress(idx_tree)
        adrs.set_tree_address(idx_tree);

        // 11:   SIG_tmp ← SIG_HT.getXMSSSignature(j)     ▷ SIGHT [ j · (h′ + len) · n : ( j + 1)(h′ + len) · n]
        let sig_tmp = sig_ht.xmss_sigs[j as usize].clone();

        // 12:   node ← xmss_PKFromSig(idx_leaf, SIG_tmp, node, PK.seed, ADRS)
        node = xmss_pk_from_sig(hashers, idx_leaf, &sig_tmp, &node, pk_seed, &adrs);

        // 13: end for
    }

    // 14: if node = PK.root then
    // 15:   return true
    // 16: else
    // 17:   return false
    // 18: end if
    node == *pk_root // TODO: CT equal
}


/// Algorithm 13: `fors_SKgen(SK.seed, PK.seed, ADRS, idx)` on page 29.
/// Generate a FORS private-key value.
///
/// Input: Secret seed `SK.seed`, public seed `PK.seed`, address `ADRS`, secret key index `idx`. <br>
/// Output: n-byte FORS private-key value.
#[allow(clippy::similar_names)] // sk_seed and pk_seed
pub(crate) fn fors_sk_gen<K: ArrayLength, LEN: ArrayLength, M: ArrayLength, N: ArrayLength>(
    hashers: &Hashers<K, LEN, M, N>, sk_seed: &[u8], pk_seed: &[u8], adrs: &Adrs, idx: u32,
) -> GenericArray<u8, N> {
    // 1: skADRS ← ADRS    ▷ Copy address to create key generation address
    let mut sk_adrs = adrs.clone();

    // 2: skADRS.setTypeAndClear(FORS_PRF)
    sk_adrs.set_type_and_clear(FORS_PRF);

    // 3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // 4: skADRS.setTreeIndex(idx)
    sk_adrs.set_tree_index(idx);

    // 5: return PRF(PK.seed, SK.seed, skADRS)
    (hashers.prf)(pk_seed, sk_seed, &sk_adrs)
}


/// Algorithm 14: `fors_node(SK.seed, i, z, PK.seed, ADRS)` on page 30.
/// Compute the root of a Merkle subtree of FORS public values.
///
/// Input: Secret seed `SK.seed`, target node index `i`, target node height `z`, public seed `PK.seed`,
/// address `ADRS`. <br>
/// Output: n-byte root node.
#[allow(clippy::similar_names)] // sk_seed and pk_seed
pub(crate) fn fors_node<
    A: ArrayLength,
    K: ArrayLength,
    LEN: ArrayLength,
    M: ArrayLength,
    N: ArrayLength,
>(
    hashers: &Hashers<K, LEN, M, N>, sk_seed: &[u8], i: u32, z: u32, pk_seed: &[u8], adrs: &Adrs,
) -> Result<GenericArray<u8, N>, &'static str> {
    let mut adrs = adrs.clone();

    // 1: if z > a or i ≥ k · 2^(a−z) then
    if (z > A::to_u32()) | (i > K::to_u32() * 2u32.pow(A::to_u32() - z)) {
        //
        // 2:   return NULL
        return Err("Alg14 fails");

        // 3: end if
    }

    // 4: if z = 0 then
    let node = if z == 0 {
        //
        // 5:    sk ← fors_SKgen(SK.seed, PK.seed, ADRS, i)
        let sk: GenericArray<u8, N> = fors_sk_gen(hashers, sk_seed, pk_seed, &adrs, i);

        // 6:    ADRS.setTreeHeight(0)
        adrs.set_tree_height(0);

        // 7:    ADRS.setTreeIndex(i)
        adrs.set_tree_index(i);

        // 8:    node ← F(PK.seed, ADRS, sk)
        (hashers.f)(pk_seed, &adrs, &sk)

        // 9:  else
    } else {
        //
        // 10:   lnode ← fors_node(SK.seed, 2i, z − 1, PK.seed, ADRS)
        let lnode = fors_node::<A, K, LEN, M, N>(hashers, sk_seed, 2 * i, z - 1, pk_seed, &adrs)?;

        // 11:   rnode ← fors_node(SK.seed, 2i + 1, z − 1, PK.seed, ADRS)
        let rnode =
            fors_node::<A, K, LEN, M, N>(hashers, sk_seed, 2 * i + 1, z - 1, pk_seed, &adrs)?;

        // 12:   ADRS.setTreeHeight(z)
        adrs.set_tree_height(z);

        // 13:   ADRS.setTreeIndex(i)
        adrs.set_tree_index(i);

        // 14:   node ← H(PK.seed, ADRS, lnode ∥ rnode)
        (hashers.h)(pk_seed, &adrs, &lnode, &rnode)

        // 15: end if
    };

    // 16: return node
    Ok(node)
}


/// Algorithm 15: `fors_sign(md, SK.seed, PK.seed, ADRS)`
/// Generate a FORS signature.
///
/// Input: Message digest `md`, secret seed `SK.seed`, address `ADRS`, public seed `PK.seed`. <br>
/// Output: FORS signature `SIG_FORS`.
#[allow(clippy::similar_names)] // sk_seed and pk_seed
pub(crate) fn fors_sign<
    A: ArrayLength,
    K: ArrayLength,
    LEN: ArrayLength,
    M: ArrayLength,
    N: ArrayLength,
>(
    hashers: &Hashers<K, LEN, M, N>, md: &[u8], sk_seed: &[u8], adrs: &Adrs, pk_seed: &[u8],
) -> Result<ForsSig<A, K, N>, &'static str> {
    // 1: SIG_FORS = NULL    ▷ Initialize SIG_FORS as a zero-length byte string
    let mut sig_fors = ForsSig::default();

    // 2: indices ← base_2^b(md, a, k)
    let mut indices: GenericArray<u32, K> = GenericArray::default();
    base_2b(md, A::to_u32(), K::to_u32(), &mut indices);


    // 3: for i from 0 to k − 1 do    ▷ Compute signature elements
    #[allow(clippy::cast_possible_truncation)]
    for i in 0..K::to_u32() {
        //
        // 4:    SIG_FORS ← SIG_FORS ∥ fors_SKgen(SK.seed, PK.seed, ADRS, i · 2^a + indices[i])
        sig_fors.private_key_value[i as usize] = fors_sk_gen::<K, LEN, M, N>(
            hashers,
            sk_seed,
            pk_seed,
            adrs,
            i * 2u32.pow(A::to_u32()) + indices[i as usize] as u32,
        );

        // 5:
        // 6:    for j from 0 to a − 1 do    ▷ Compute auth path
        for j in 0..A::to_u32() {
            //
            // 7:      s ← indices[i]/2^j xor 1
            let s = (indices[i as usize] >> j) ^ 1;

            // 8:      AUTH[j] ← fors_node(SK.seed, i · 2^{a−j} + s, j, PK.seed, ADRS)
            sig_fors.auth[i as usize].tree[j as usize] = fors_node::<A, K, LEN, M, N>(
                hashers,
                sk_seed,
                i * 2u32.pow(A::to_u32() - j) + s as u32,
                j,
                pk_seed,
                adrs,
            )?;

            // 9:    end for
        }

        // 10:   SIG_FORS ← SIG_FORS ∥ AUTH
        // built within inner loop above

        // 11: end for
    }

    // 12: return SIG_FORS
    Ok(sig_fors)
}


/// Algorithm 16: `fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)` on page 32.
/// Compute a FORS public key from a FORS signature.
///
/// Input: FORS signature `SIG_FORS`, message digest `md`, public seed `PK.seed`, address `ADRS`. <br>
/// Output: FORS public key.
pub(crate) fn fors_pk_from_sig<
    A: ArrayLength,
    K: ArrayLength,
    LEN: ArrayLength,
    M: ArrayLength,
    N: ArrayLength,
>(
    hashers: &Hashers<K, LEN, M, N>, sig_fors: &ForsSig<A, K, N>, md: &[u8], pk_seed: &[u8],
    adrs: &Adrs,
) -> ForsPk<N> {
    let mut adrs = adrs.clone();

    // 1: indices ← base_2^b(md, a, k)
    let mut indices: GenericArray<u32, K> = GenericArray::default();
    base_2b(md, A::to_u32(), K::to_u32(), &mut indices);


    // 2: for i from 0 to k − 1 do
    let mut root: GenericArray<GenericArray<u8, N>, K> = GenericArray::default();
    #[allow(clippy::cast_possible_truncation)] // Step 5
    for i in 0..K::to_u32() {
        //
        // 3:   sk ← SIG_FORS.getSK(i)    ▷ SIG_FORS [i · (a + 1) · n : (i · (a + 1) + 1) · n]
        let sk = sig_fors.private_key_value[i as usize].clone();

        // 4:   ADRS.setTreeHeight(0)    ▷ Compute leaf
        adrs.set_tree_height(0);

        // 5:   ADRS.setTreeIndex(i · 2^a + indices[i])
        adrs.set_tree_index(i * 2u32.pow(A::to_u32()) + indices[i as usize] as u32);

        // 6:   node[0] ← F(PK.seed, ADRS, sk)
        let mut node_0 = (hashers.f)(pk_seed, &adrs, &sk);

        // 7:
        // 8: auth ← SIGFORS.getAUTH(i)    ▷ SIGFORS [(i · (a + 1) + 1) · n : (i + 1) · (a + 1) · n]
        let auth = sig_fors.auth[i as usize].clone();

        // 9: for j from 0 to a − 1 do    ▷ Compute root from leaf and AUTH
        for j in 0..A::to_u32() {
            //
            // 10:  ADRS.setTreeHeight(j + 1)
            adrs.set_tree_height(j + 1);

            // 11:  if indices[i]/2^j is even then
            let node_1 = if ((indices[i as usize] >> j) % 2) == 0 {
                //
                // 12:    ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
                let tmp = adrs.get_tree_index() / 2;
                adrs.set_tree_index(tmp);

                // 13:    node[1] ← H(PK.seed, ADRS, node[0] ∥ auth[j])
                (hashers.h)(pk_seed, &adrs, &node_0, &auth.tree[j as usize])

                // 14:  else
            } else {
                //
                // 15:    ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
                let tmp = (adrs.get_tree_index() - 1) / 2;
                adrs.set_tree_index(tmp);

                // 16:    node[1] ← H(PK.seed, ADRS, auth[j] ∥ node[0])
                (hashers.h)(pk_seed, &adrs, &auth.tree[j as usize], &node_0)

                // 17:  end if
            };

            // 18: node[0] ← node[1]
            node_0 = node_1;

            // 19: end for
        }

        // 20: root[i] ← node[0]
        root[i as usize] = node_0;

        // 21: end for
    }

    // 22: forspkADRS ← ADRS    ▷ Compute the FORS public key from the Merkle tree roots
    let mut fors_pk_adrs = adrs.clone();

    // 23: forspkADRS.setTypeAndClear(FORS_ROOTS)
    fors_pk_adrs.set_type_and_clear(FORS_ROOTS);

    // 24: forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // 25: pk ← Tk(PK.seed, forspkADRS, root)
    let pk = (hashers.t_len)(pk_seed, &fors_pk_adrs, &root);

    // 26: return pk;
    ForsPk { key: pk }
}


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
    let pk_root =
        xmss_node::<H, HP, K, LEN, M, N>(hashers, &sk_seed, 0, HP::to_u32(), &pk_seed, &adrs)?;

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
    // 1: ADRS ← toByte(0, 32)
    let mut adrs = Adrs::default();

    // 2:
    // 3: opt_rand ← PK.seed    ▷ Set opt_rand to either PK.seed
    let mut opt_rand = sk.pk_seed.clone();

    // 4: if (RANDOMIZE) then    ▷ or to a random n-byte string
    if randomize {
        // 5:   opt_rand ←$ Bn
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
    let index1 = (K::to_usize() * A::to_usize()).div_ceil(8);
    let md = &digest[0..index1];

    // 12: tmp_idx_tree ← digest[ceil(k·a/8) : ceil(k·a/8) + ceil((h-h/d)/8)]    ▷ next ceil((h-h/d)/8) bytes
    let index2 = index1 + (H::to_usize() - H::to_usize() / D::to_usize()).div_ceil(8);
    let tmp_idx_tree = &digest[index1..index2];

    // 13: tmp_idx_leaf ← digest[ceil(k·a/8) + ceil((h-h/d)/8) : ceil(k·a/8) + ceil((h-h/d)/8) + ceil(h/8d)]    ▷ next ceil(h/8d) bytes
    let index3 = index2 + H::to_usize().div_ceil(8 * D::to_usize());
    let tmp_idx_leaf = &digest[index2..index3];

    // 14:
    // 15: idx_tree ← toInt(tmp_idx_tree, ceil((h-h/d)/8)) mod 2^{h−h/d}
    let idx_tree =
        to_int(tmp_idx_tree, (H::to_usize() - H::to_usize() / D::to_usize()).div_ceil(8))
            & (u64::MAX >> (64 - (H::to_u32() - H::to_u32() / D::to_u32())));
    // % 2u64.pow(H::to_u32() - H::to_u32() / D::to_u32()); // Can be 2^64

    // 16: idx_leaf ← toInt(tmp_idx_leaf, ceil(h/8d) mod 2^{h/d}
    let idx_leaf = to_int(tmp_idx_leaf, H::to_usize().div_ceil(8 * D::to_usize()))
        % 2u64.pow(H::to_u32() / D::to_u32());

    // 17:
    // 18: ADRS.setTreeAddress(idx_tree)
    adrs.set_tree_address(idx_tree);

    // 19: ADRS.setTypeAndClear(FORS_TREE)
    adrs.set_type_and_clear(FORS_TREE);

    // 20: ADRS.setKeyPairAddress(idxleaf)
    adrs.set_key_pair_address(idx_leaf as u32);

    // 21: SIG_FORS ← fors_sign(md, SK.seed, PK.seed, ADRS)
    // 22: SIG ← SIG ∥ SIG_FORS
    sig.fors_sig = fors_sign(hashers, md, &sk.sk_seed, &adrs, &sk.pk_seed)?;

    // 23:
    // 24: PK_FORS ← fors_pkFromSig(SIG_FORS , md, PK.seed, ADRS)    ▷ Get FORS key
    let pk_fors =
        fors_pk_from_sig::<A, K, LEN, M, N>(hashers, &sig.fors_sig, md, &sk.pk_seed, &adrs);

    // 25:
    // 26: SIG_HT ← ht_sign(PK_FORS , SK.seed, PK.seed, idx_tree, idx_leaf)
    // 27: SIG ← SIG ∥ SIG_HT
    sig.ht_sig = ht_sign::<D, H, HP, K, LEN, M, N>(
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
    let digest = (hashers.h_msg)(&r, &pk.pk_seed, &pk.pk_root, m);

    // 10: md ← digest[0 : ceil(k·a/8)]    ▷ first ceil(k·a/8) bytes
    let index1 = (K::to_usize() * A::to_usize()).div_ceil(8);
    let md = &digest[0..index1];

    // 11: tmp_idx_tree ← digest[ceil(k·a/8) : ceil(k·a/8) + ceil((h - h/d)/8)]     ▷ next ceil((h - h/d)/8) bytes
    let index2 = index1 + (H::to_usize() - H::to_usize() / D::to_usize()).div_ceil(8);
    let tmp_idx_tree = &digest[index1..index2];

    // 12: tmp_idx_leaf ← digest[ceil(k·a/8) + ceil((h - h/d)/8) : ceil(k·a/8) + ceil((h - h/d)/8) + ceil(h/8d)]  ▷ next ceil(h/8d) bytes
    let index3 = index2 + H::to_usize().div_ceil(8 * D::to_usize());
    let tmp_idx_leaf = &digest[index2..index3];

    // 13:
    // 14: idx_tree ← toInt(tmp_idx_tree, ceil((h - h/d)/8)) mod 2^{h−h/d}
    let idx_tree =
        to_int(tmp_idx_tree, (H::to_usize() - H::to_usize() / D::to_usize()).div_ceil(8))
            & (u64::MAX >> (64 - (H::to_u32() - H::to_u32() / D::to_u32())));
    // % 2u64.pow(H::to_u32() - H::to_u32() / D::to_u32());  // Can be 2^64

    // 15: idx_leaf ← toInt(tmp_idx_leaf, ceil(h/8d) mod 2^{h/d}
    let idx_leaf = to_int(tmp_idx_leaf, H::to_usize().div_ceil(8 * D::to_usize()))
        % 2u64.pow(H::to_u32() / D::to_u32());

    // 16:
    // 17: ADRS.setTreeAddress(idx_tree)    ▷ Compute FORS public key
    adrs.set_tree_address(idx_tree);

    // 18: ADRS.setTypeAndClear(FORS_TREE)
    adrs.set_type_and_clear(FORS_TREE);

    // 19: ADRS.setKeyPairAddress(idx_leaf)
    adrs.set_key_pair_address(idx_leaf as u32);

    // 20:
    // 21: PK_FORS ← fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)
    let pk_fors = fors_pk_from_sig::<A, K, LEN, M, N>(hashers, sig_fors, md, &pk.pk_seed, &adrs);


    // 22:
    // 23: return ht_verify(PK_FORS, SIG_HT, PK.seed, idx_tree , idx_leaf, PK.root)
    ht_verify::<D, HP, K, LEN, M, N>(
        hashers,
        &pk_fors.key,
        sig_ht,
        &pk.pk_seed,
        idx_tree,
        idx_leaf as u32,
        &pk.pk_root,
    )
}
