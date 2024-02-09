use crate::types::{Adrs, SlhDsaSig};
use generic_array::ArrayLength;


/// Algorithm 1: `toInt(X, n)` on page 14.
/// Convert a byte string to an integer.
///
/// Input: n-byte string `X`, string length `n`. <br>
/// Output: Integer value of `X`.
pub(crate) fn to_int(x: &[u8], n: u32) -> u64 {
    debug_assert_eq!(x.len(), n as usize);
    debug_assert!(n <= 8);

    // 1: total ← 0
    let mut total = 0;

    // 2:
    // 3: for i from 0 to n − 1 do
    for item in x.iter().take(n as usize) {
        //
        // 4: total ← 256 · total + X[i]
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
pub(crate) fn to_byte(x: u32, n: u32) -> [u8; ((crate::LEN2 * crate::LGW + 7) / 8) as usize] {
    let mut s = [0u8; ((crate::LEN2 * crate::LGW + 7) / 8) as usize]; // Size fixed across all profiles (2)
    debug_assert_eq!(n, ((crate::LEN2 * crate::LGW + 7) / 8)); // just in case life changes
    debug_assert_eq!(n, 2); // optimize: this resolves into a two-byte (be) write!

    // 1: total ← x
    let mut total = x;

    // 2:
    // 3: for i from 0 to n − 1 do
    for i in 0..n {
        //
        // 4: S[n − 1 − i] ← total mod 256    ▷ Least significant 8 bits of total
        s[(n - 1 - i) as usize] = total.to_le_bytes()[0];

        // 5: total ← total ≫ 8
        total >>= 8;

        // 6: end for
    }

    // 7: return S
    s
}


/// Algorithm 3: `base_2^b(X, b, out_len)` on page 15.
/// Compute the base 2^b representation of X.
///
/// Input: Byte string `X` of length at least `ceil(out_len·b/8)`, integer `b`, output length `out_len`. <br>
/// Output: Array of `out_len` integers in the range `[0, . . . , 2^b − 1]`.
pub(crate) fn base_2b(x: &[u8], b: u32, out_len: u32, baseb: &mut [u32]) {
    debug_assert!(x.len() >= (out_len * b).div_ceil(8) as usize);
    debug_assert!(b < 16); // Consider optimizing `baseb` output to be u16
    debug_assert_eq!(out_len as usize, baseb.len());

    // 1: in ← 0
    let mut inn = 0;

    // 2: bits ← 0
    let mut bits = 0;

    // 3: total ← 0
    let mut total = 0;

    // 4:
    // 5: for out from 0 to out_len − 1 do
    for item in baseb.iter_mut() {
        //
        // 6: while bits < b do
        while bits < b {
            //
            // 7: total ← (total ≪ 8) + X[in]
            total = (total << 8) + u32::from(x[inn]);

            // 8: in ← in + 1
            inn += 1;

            // 9: bits ← bits + 8
            bits += 8;

            // 10: end while
        }

        // 11: bits ← bits − b
        bits -= b;

        // 12: baseb[out] ← (total ≫ bits) mod 2^b
        *item = (total >> bits) & (u32::MAX >> (32 - b));

        // 13: end for
    }

    // 14: return baseb  (mutable parameter)
}


impl<
        A: ArrayLength,
        D: ArrayLength,
        HP: ArrayLength,
        K: ArrayLength,
        LEN: ArrayLength,
        N: ArrayLength,
    > SlhDsaSig<A, D, HP, K, LEN, N>
{
    pub(crate) fn deserialize<const SIG_LEN: usize>(self) -> [u8; SIG_LEN] {
        let mut out = [0u8; SIG_LEN];
        debug_assert_eq!(
            out.len(),
            N::to_usize() +  // randomness
                N::to_usize() * K::to_usize() + K::to_usize() * A::to_usize() * N::to_usize() + // ForsSig
                D::to_usize() * (HP::to_usize() * N::to_usize() + LEN::to_usize() * N::to_usize())
        );
        out[0..N::to_usize()].copy_from_slice(&self.randomness);
        let mut start = N::to_usize();
        for k in 0..K::to_usize() {
            out[start..(start + N::to_usize())]
                .copy_from_slice(&self.fors_sig.private_key_value[k]);
            start += N::to_usize();
            for a in 0..A::to_usize() {
                out[start..(start + N::to_usize())].copy_from_slice(&self.fors_sig.auth[k].tree[a]);
                start += N::to_usize();
            }
        }
        for d in 0..D::to_usize() {
            //println!("and we move to xmss {} starting at {}", d, start);
            for len in 0..LEN::to_usize() {
                out[start..(start + N::to_usize())]
                    .copy_from_slice(&self.ht_sig.xmss_sigs[d].sig_wots.data[len]);
                start += N::to_usize();
            }
            for hp in 0..HP::to_usize() {
                out[start..(start + N::to_usize())]
                    .copy_from_slice(&self.ht_sig.xmss_sigs[d].auth[hp]);
                start += N::to_usize();
            }
        }
        debug_assert_eq!(start, out.len());
        out
    }

    pub(crate) fn serialize(bytes: &[u8]) -> Self {
        debug_assert_eq!(
            bytes.len(),
            N::to_usize() +  // randomness
                N::to_usize() * K::to_usize() + K::to_usize() * A::to_usize() * N::to_usize() + // ForsSig
                D::to_usize() * (HP::to_usize() * N::to_usize() + LEN::to_usize() * N::to_usize())
        );
        let mut output = Self::default();
        output.randomness.copy_from_slice(&bytes[0..N::to_usize()]);
        let mut start = N::to_usize();
        for k in 0..K::to_usize() {
            output.fors_sig.private_key_value[k]
                .copy_from_slice(&bytes[start..(start + N::to_usize())]);
            start += N::to_usize();
            for a in 0..A::to_usize() {
                output.fors_sig.auth[k].tree[a]
                    .copy_from_slice(&bytes[start..(start + N::to_usize())]);
                start += N::to_usize();
            }
        }
        for d in 0..D::to_usize() {
            for len in 0..LEN::to_usize() {
                output.ht_sig.xmss_sigs[d].sig_wots.data[len]
                    .copy_from_slice(&bytes[start..(start + N::to_usize())]);
                start += N::to_usize();
            }
            for hp in 0..HP::to_usize() {
                output.ht_sig.xmss_sigs[d].auth[hp]
                    .copy_from_slice(&bytes[start..(start + N::to_usize())]);
                start += N::to_usize();
            }
        }
        debug_assert_eq!(start, bytes.len());
        output
    }
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

    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn set_tree_address(&mut self, t: u64) {
        self.f2 = ((t >> 32) as u32).to_be_bytes();
        self.f3 = (t as u32).to_be_bytes();
    }

    pub(crate) fn set_hash_address(&mut self, addr: u32) { self.f7 = addr.to_be_bytes() }

    pub(crate) fn set_tree_height(&mut self, z: u32) { self.f6 = z.to_be_bytes() }

    pub(crate) fn get_tree_index(&mut self) -> u32 { u32::from_be_bytes(self.f7) }

    pub(crate) fn set_tree_index(&mut self, i: u32) { self.f7 = i.to_be_bytes() }

    pub(crate) fn to_32_bytes(&self) -> [u8; 32] {
        let mut ret = [0u8; 32];
        let mut start = 0;
        for sl in [
            self.f0, self.f1, self.f2, self.f3, self.f4, self.f5, self.f6, self.f7,
        ] {
            ret[start..start + 4].copy_from_slice(&sl);
            start += 4;
        }
        ret
    }

    pub(crate) fn to_22_bytes(&self) -> [u8; 22] {
        let mut ret = [0u8; 22];
        ret[0] = self.f0[3];
        ret[1..5].copy_from_slice(&self.f2);
        ret[5..9].copy_from_slice(&self.f3);
        ret[9] = self.f4[3];
        ret[10..14].copy_from_slice(&self.f5);
        ret[14..18].copy_from_slice(&self.f6);
        ret[18..22].copy_from_slice(&self.f7);
        ret
    }
}
