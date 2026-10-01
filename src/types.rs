use zeroize::{Zeroize, ZeroizeOnDrop};


/// DER-encoded OIDs for pre-hash functions used with HashSLH-DSA.
/// See RFC 6234 (for SHA2), RFC 9688 (for SHA3), and RFC 8702 (for SHAKE).
/// These are all within the OID space prefixed by 2.16.840.1.101.3.4.2, a.k.a.
/// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2)
/// See also <https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#Hash>
///
/// FIPS 205 §10.2.2 lists SHA-256, SHA-512, SHAKE128, and SHAKE256 and allows other
/// approved hash functions. The caller supplies `PH(M)` and one of these OIDs.
pub mod pre_hash {
    #![allow(dead_code)]

    /// DER-encoded OID for id-sha224
    pub const SHA2_224: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
    /// DER-encoded OID for id-sha256
    pub const SHA2_256: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    /// DER-encoded OID for id-sha384
    pub const SHA2_384: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    /// DER-encoded OID for id-sha512
    pub const SHA2_512: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
    /// DER-encoded OID for id-sha512-224
    pub const SHA2_512_224: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05];
    /// DER-encoded OID for id-sha512-256
    pub const SHA2_512_256: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06];
    /// DER-encoded OID for id-sha3-224
    pub const SHA3_224: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07];
    /// DER-encoded OID for id-sha3-256
    pub const SHA3_256: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08];
    /// DER-encoded OID for id-sha3-384
    pub const SHA3_384: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09];
    /// DER-encoded OID for id-sha3-512
    pub const SHA3_512: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A];
    /// DER-encoded OID for id-shake128
    pub const SHAKE_128: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B];
    /// DER-encoded OID for id-shake256
    pub const SHAKE_256: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C];
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
    pub(crate) f0: [u8; 4],
    // layer address
    pub(crate) f1: [u8; 4],
    // tree address
    pub(crate) f2: [u8; 4],
    // tree address
    pub(crate) f3: [u8; 4],
    // tree address
    pub(crate) f4: [u8; 4],
    // type
    pub(crate) f5: [u8; 4],
    // key pair address OR padding
    pub(crate) f6: [u8; 4],
    // chain address OR padding OR tree height
    pub(crate) f7: [u8; 4], // hash address OR padding OR tree index OR hash address = 0
}
