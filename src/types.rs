use alloc::vec::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

const WOTS_HASH: u32 = 0;
pub(crate) const WOTS_PK: u32 = 1;
const TREE: u32 = 2;
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
pub(crate) const WOTS_PRF: u32 = 5;
const FORS_PRF: u32 = 6;


/// Straddling the line between struct, enum and union...
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
#[repr(align(32))]
pub struct ADRS {
    f0: [u8; 4], // layer address
    f1: [u8; 4], // tree address (LSB?)
    f2: [u8; 4], // tree address
    f3: [u8; 4], // tree address (MSB)
    f4: [u8; 4], // type
    f5: [u8; 4], // key pair address OR padding
    f6: [u8; 4], // chain address OR padding OR tree height
    f7: [u8; 4], // hash address OR padding ORtree index OR hash address = 0
}


impl ADRS {
    pub(crate) fn get_key_pair_address(&self) -> [u8; 4] { self.f5 }

    pub(crate) fn set_key_pair_address(&mut self, kp_addr: [u8; 4]) { self.f5 = kp_addr; }

    pub(crate) fn set_chain_address(&mut self, i: usize) { self.f6 = (i as u32).to_be_bytes(); }

    pub(crate) fn set_type_and_clear(&mut self, type_t: u32) {
        self.f4 = type_t.to_be_bytes();
        self.f5 = 0u32.to_be_bytes();
        self.f6 = 0u32.to_be_bytes();
        self.f7 = 0u32.to_be_bytes();
    }

    pub(crate) fn set_hash_address(&mut self, addr: u32) { self.f7 = addr.to_be_bytes(); }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let x = [self.f0, self.f1, self.f2, self.f3].concat();
        x
    }
}
