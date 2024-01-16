use alloc::vec::Vec;
use generic_array::{ArrayLength, GenericArray};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fig 16 on page 34
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SlhDsaSig<
    A: ArrayLength,
    D: ArrayLength,
    HP: ArrayLength,
    K: ArrayLength,
    LEN: ArrayLength,
    N: ArrayLength,
> {
    randomness: GenericArray<u8, N>,
    fors_sig: ForsSig<A, K, N>,
    ht_sig: HtSig<D, HP, LEN, N>,
}

/// Fig 13 on page 29
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ForsSig<A: ArrayLength, K: ArrayLength, N: ArrayLength> {
    private_key_value: GenericArray<GenericArray<u8, N>, K>,
    auth: GenericArray<Auth<A, N>, K>,
}

/// Fig 10?
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Auth<A: ArrayLength, N: ArrayLength> {
    tree: GenericArray<GenericArray<u8, N>, A>,
}

#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub(crate) struct HtSig<D: ArrayLength, HP: ArrayLength, LEN: ArrayLength, N: ArrayLength> {
    pub(crate) xmss_sigs: GenericArray<XmssSig<HP, LEN, N>, D>,
}

#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct WotsSig<LEN: ArrayLength, N: ArrayLength> {
    pub(crate) data: GenericArray<GenericArray<u8, N>, LEN>,
}

#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct WotsPk<N: ArrayLength>(pub(crate) GenericArray<u8, N>);


#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct XmssSig<HP: ArrayLength, LEN: ArrayLength, N: ArrayLength> {
    pub(crate) sig_wots: WotsSig<LEN, N>,
    pub(crate) auth: GenericArray<GenericArray<u8, N>, HP>,
}

impl<HP: ArrayLength, LEN: ArrayLength, N: ArrayLength> XmssSig<HP, LEN, N> {
    pub(crate) fn get_wots_sig(&self) -> &WotsSig<LEN, N> { &self.sig_wots }

    pub(crate) fn get_xmss_auth(&self) -> &GenericArray<GenericArray<u8, N>, HP> { &self.auth }
}

pub(crate) const WOTS_HASH: u32 = 0;
pub(crate) const WOTS_PK: u32 = 1;
pub(crate) const TREE: u32 = 2;
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
pub(crate) const WOTS_PRF: u32 = 5;
const FORS_PRF: u32 = 6;

/// Straddling the line between struct, enum and union...
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
#[repr(align(32))]
pub struct Adrs {
    f0: [u8; 4], // layer address
    f1: [u8; 4], // tree address (LSB?)
    f2: [u8; 4], // tree address
    f3: [u8; 4], // tree address (MSB)
    f4: [u8; 4], // type
    f5: [u8; 4], // key pair address OR padding
    f6: [u8; 4], // chain address OR padding OR tree height
    f7: [u8; 4], // hash address OR padding OR tree index OR hash address = 0
}

impl Adrs {
    pub(crate) fn set_layer_address(&mut self, la: u32) { self.f0 = la.to_be_bytes() }

    pub(crate) fn get_key_pair_address(&self) -> u32 { u32::from_be_bytes(self.f5) }

    pub(crate) fn set_key_pair_address(&mut self, kp_addr: u32) { self.f5 = kp_addr.to_be_bytes(); }

    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn set_chain_address(&mut self, i: u32) { self.f6 = i.to_be_bytes(); }

    pub(crate) fn set_type_and_clear(&mut self, type_t: u32) {
        self.f4 = type_t.to_be_bytes();
        self.f5 = 0u32.to_be_bytes();
        self.f6 = 0u32.to_be_bytes();
        self.f7 = 0u32.to_be_bytes();
    }

    pub(crate) fn set_tree_address(&mut self, t: u32) { self.f1 = t.to_be_bytes() }

    // TODO: revisit 16 bytes

    pub(crate) fn set_hash_address(&mut self, addr: u32) { self.f7 = addr.to_be_bytes() }

    pub(crate) fn set_tree_height(&mut self, z: u32) { self.f6 = z.to_be_bytes() }

    pub(crate) fn get_tree_index(&mut self) -> u32 { u32::from_be_bytes(self.f7) }

    pub(crate) fn set_tree_index(&mut self, i: u32) { self.f7 = i.to_be_bytes() }

    pub(crate) fn to_bytes(&self) -> Vec<u8> { [self.f0, self.f1, self.f2, self.f3].concat() }
}
