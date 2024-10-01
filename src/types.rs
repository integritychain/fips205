use zeroize::{Zeroize, ZeroizeOnDrop};


/// Fig 16 on page 34
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


#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SlhPublicKey<const N: usize> {
    pub(crate) pk_seed: [u8; N],
    pub(crate) pk_root: [u8; N],
}


#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SlhPrivateKey<const N: usize> {
    pub(crate) sk_seed: [u8; N],
    pub(crate) sk_prf: [u8; N],
    pub(crate) pk_seed: [u8; N],
    pub(crate) pk_root: [u8; N],
}


/// Fig 13 on page 29
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ForsSig<const A: usize, const K: usize, const N: usize> {
    pub(crate) private_key_value: [[u8; N]; K],
    pub(crate) auth: [Auth<A, N>; K],
}


#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ForsPk<const N: usize> {
    pub(crate) key: [u8; N],
}


/// Fig 10
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Auth<const A: usize, const N: usize> {
    pub(crate) tree: [[u8; N]; A],
}


#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct HtSig<const D: usize, const HP: usize, const LEN: usize, const N: usize> {
    pub(crate) xmss_sigs: [XmssSig<HP, LEN, N>; D],
}


#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct WotsSig<const LEN: usize, const N: usize> {
    pub(crate) data: [[u8; N]; LEN],
}


#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WotsPk<const N: usize>(pub(crate) [u8; N]);


#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct XmssSig<const HP: usize, const LEN: usize, const N: usize> {
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
#[repr(align(32))]
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
