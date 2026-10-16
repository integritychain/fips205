use zeroize::{Zeroize, ZeroizeOnDrop};


/// DER-encoded OIDs for pre-hash functions used with HashSLH-DSA.
/// See RFC 6234 (for SHA2), RFC 9688 (for SHA3), and RFC 8702 (for SHAKE).
/// These are all within the OID space prefixed by 2.16.840.1.101.3.4.2, a.k.a.
/// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2)
/// See also <https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#Hash>
///
/// FIPS 205 §10.2.2 lists SHA-256, SHA-512, SHAKE128, and SHAKE256 and allows other
/// approved hash functions. The caller supplies `PH(M)` and one of these OIDs.
///
/// The caller hashes the message. With one of these OIDs, `try_hash_sign` and `hash_verify` need
/// the whole digest: 28 bytes for the -224 functions, 32 for the -256 functions and SHAKE128
/// (256-bit output), 48 for the -384 functions, and 64 for the -512 functions and SHAKE256
/// (512-bit output). Another OID must be DER-encoded and takes a digest of up to 1024 bytes.
/// FIPS 205 §10.2.1 notes that keeping the parameter set's collision strength needs a digest of
/// at least 2n bytes: 32 for the 128-bit sets, 48 for the 192-bit sets and 64 for the 256-bit sets.
pub mod pre_hash {
    #![allow(dead_code)]

    /// DER-encoded OID for id-sha224
    pub const SHA2_224: [u8; 11] =
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
    /// DER-encoded OID for id-sha256
    pub const SHA2_256: [u8; 11] =
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    /// DER-encoded OID for id-sha384
    pub const SHA2_384: [u8; 11] =
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    /// DER-encoded OID for id-sha512
    pub const SHA2_512: [u8; 11] =
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
    /// DER-encoded OID for id-sha512-224
    pub const SHA2_512_224: [u8; 11] =
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05];
    /// DER-encoded OID for id-sha512-256
    pub const SHA2_512_256: [u8; 11] =
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06];
    /// DER-encoded OID for id-sha3-224
    pub const SHA3_224: [u8; 11] =
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07];
    /// DER-encoded OID for id-sha3-256
    pub const SHA3_256: [u8; 11] =
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08];
    /// DER-encoded OID for id-sha3-384
    pub const SHA3_384: [u8; 11] =
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09];
    /// DER-encoded OID for id-sha3-512
    pub const SHA3_512: [u8; 11] =
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A];
    /// DER-encoded OID for id-shake128
    pub const SHAKE_128: [u8; 11] =
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B];
    /// DER-encoded OID for id-shake256
    pub const SHAKE_256: [u8; 11] =
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C];

    /// The digest length in bytes for each OID above. SHAKE128 and SHAKE256 output 256 and 512
    /// bits, as in FIPS 205 Algorithm 23.
    const DIGEST_LENS: [(&[u8], usize); 12] = [
        (&SHA2_224, 28),
        (&SHA2_256, 32),
        (&SHA2_384, 48),
        (&SHA2_512, 64),
        (&SHA2_512_224, 28),
        (&SHA2_512_256, 32),
        (&SHA3_224, 28),
        (&SHA3_256, 32),
        (&SHA3_384, 48),
        (&SHA3_512, 64),
        (&SHAKE_128, 32),
        (&SHAKE_256, 64),
    ];

    /// The digest length in bytes for an OID in this module, or `None` for any other OID.
    pub(crate) fn digest_len(oid: &[u8]) -> Option<usize> {
        DIGEST_LENS.iter().find(|(known, _)| *known == oid).map(|(_, len)| *len)
    }
}


/// Fig 17 on page 34
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SlhDsaSig<
    const A: usize,
    const D: usize,
    const HP: usize,
    const K: usize,
    const LEN: usize,
    const N: usize,
> {
    pub(crate) randomness: [u8; N],
    pub(crate) fors_sig: ForsSig<A, K, N>,
    pub(crate) ht_sig: HtSig<D, HP, LEN, N>,
}


/// Fig 16 on page 33
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SlhPublicKey<const N: usize> {
    pub(crate) pk_seed: [u8; N],
    pub(crate) pk_root: [u8; N],
}


/// Fig 15 on page 33
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SlhPrivateKey<const N: usize> {
    pub(crate) sk_seed: [u8; N],
    pub(crate) sk_prf: [u8; N],
    pub(crate) pk_seed: [u8; N],
    pub(crate) pk_root: [u8; N],
}


/// Fig 14 on page 29
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ForsSig<const A: usize, const K: usize, const N: usize> {
    pub(crate) private_key_value: [[u8; N]; K],
    pub(crate) auth: [Auth<A, N>; K],
}


#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ForsPk<const N: usize> {
    pub(crate) key: [u8; N],
}


#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Auth<const A: usize, const N: usize> {
    pub(crate) tree: [[u8; N]; A],
}


/// Fig 13 on page 26
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct HtSig<const D: usize, const HP: usize, const LEN: usize, const N: usize> {
    pub(crate) xmss_sigs: [XmssSig<HP, LEN, N>; D],
}


/// Fig 10 on page 19
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct WotsSig<const LEN: usize, const N: usize> {
    pub(crate) data: [[u8; N]; LEN],
}


#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct WotsPk<const N: usize>(pub(crate) [u8; N]);


/// Fig 11 on page 22
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct XmssSig<const HP: usize, const LEN: usize, const N: usize> {
    pub(crate) sig_wots: WotsSig<LEN, N>,
    pub(crate) auth: [[u8; N]; HP],
}


impl<const HP: usize, const LEN: usize, const N: usize> XmssSig<HP, LEN, N> {
    pub(crate) fn get_wots_sig(&self) -> &WotsSig<LEN, N> { &self.sig_wots }

    pub(crate) fn get_xmss_auth(&self) -> &[[u8; N]; HP] { &self.auth }
}


pub(crate) const WOTS_HASH: u32 = 0;
pub(crate) const WOTS_PK: u32 = 1;
pub(crate) const TREE: u32 = 2;
pub(crate) const FORS_TREE: u32 = 3;
pub(crate) const FORS_ROOTS: u32 = 4;
pub(crate) const WOTS_PRF: u32 = 5;
pub(crate) const FORS_PRF: u32 = 6;


/// Straddling the line between struct, enum and union...
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
#[repr(align(32))] // TODO: check alignment size perf/requirements
pub(crate) struct Adrs {
    // layer address
    pub(crate) f0: [u8; 4],
    // tree address
    pub(crate) f1: [u8; 4],
    // tree address
    pub(crate) f2: [u8; 4],
    // tree address
    pub(crate) f3: [u8; 4],
    // type
    pub(crate) f4: [u8; 4],
    // key pair address OR padding
    pub(crate) f5: [u8; 4],
    // chain address OR padding OR tree height
    pub(crate) f6: [u8; 4],
    // hash address OR padding OR tree index OR hash address = 0
    pub(crate) f7: [u8; 4],
}
