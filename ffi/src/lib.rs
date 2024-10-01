use fips205;
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
use std::convert::TryInto;

use std::os::raw::c_int;

pub const SLH_DSA_OK: u8 = 0;
pub const SLH_DSA_NULL_PTR_ERROR: u8 = 1;
pub const SLH_DSA_SERIALIZATION_ERROR: u8 = 2;
pub const SLH_DSA_DESERIALIZATION_ERROR: u8 = 3;
pub const SLH_DSA_KEYGEN_ERROR: u8 = 4;
pub const SLH_DSA_SIGN_ERROR: u8 = 5;
pub const SLH_DSA_VERIFY_ERROR: u8 = 6;

#[repr(C)]
pub struct slh_dsa_message {
    data: [u8],
}


// slh_dsa_sha2_128f

#[repr(C)]
pub struct slh_dsa_sha2_128f_private_key {
    data: [u8; fips205::slh_dsa_sha2_128f::SK_LEN],
}

#[repr(C)]
pub struct slh_dsa_sha2_128f_public_key {
    data: [u8; fips205::slh_dsa_sha2_128f::PK_LEN],
}

#[repr(C)]
pub struct slh_dsa_sha2_128f_signature {
    data: [u8; fips205::slh_dsa_sha2_128f::SIG_LEN],
}


#[no_mangle]
pub extern "C" fn slh_dsa_sha2_128f_keygen(
    public_out: Option<&mut slh_dsa_sha2_128f_public_key>,
    private_out: Option<&mut slh_dsa_sha2_128f_private_key>,
) -> u8 {
    //use fips205::traits::{KeyGen, SerDes};

    let (Some(public_out), Some(private_out)) = (public_out, private_out) else {
        return SLH_DSA_NULL_PTR_ERROR;
    };
    let Ok((pk, sk)) = fips205::slh_dsa_sha2_128f::KG::try_keygen() else {
        return SLH_DSA_KEYGEN_ERROR;
    };

    public_out.data = pk.into_bytes();
    private_out.data = sk.into_bytes();
    return SLH_DSA_OK;
}


#[no_mangle]
pub extern "C" fn slh_dsa_sha2_128f_sign(
    message_buf: *const u8, message_len: c_int,
    private_key: Option<&mut slh_dsa_sha2_128f_private_key>,
    signature_out: Option<&mut slh_dsa_sha2_128f_signature>,
) -> u8 {
    let (Some(private_key), Some(signature_out)) = (private_key, signature_out) else {
        return SLH_DSA_NULL_PTR_ERROR;
    };

    if message_buf.is_null() {
        return SLH_DSA_NULL_PTR_ERROR;
    };

    let message =
        unsafe { std::slice::from_raw_parts(message_buf, message_len.try_into().unwrap()) };

    let Ok(sk) = fips205::slh_dsa_sha2_128f::PrivateKey::try_from_bytes(&private_key.data) else {
        return SLH_DSA_DESERIALIZATION_ERROR;
    };
    let Ok(sig) = sk.try_sign(&message, true) else {
        return SLH_DSA_SIGN_ERROR;
    };
    signature_out.data = sig;
    return SLH_DSA_OK;
}

#[no_mangle]
pub extern "C" fn slh_dsa_sha2_128f_verify(
    message_buf: *const u8, message_len: c_int,
    public_key: Option<&mut slh_dsa_sha2_128f_public_key>,
    signature: Option<&mut slh_dsa_sha2_128f_signature>,
) -> u8 {
    let (Some(public_key), Some(signature)) = (public_key, signature) else {
        return SLH_DSA_NULL_PTR_ERROR;
    };
    let message =
        unsafe { std::slice::from_raw_parts(message_buf, message_len.try_into().unwrap()) };

    let Ok(sk) = fips205::slh_dsa_sha2_128f::PublicKey::try_from_bytes(&public_key.data) else {
        return SLH_DSA_DESERIALIZATION_ERROR;
    };
    let res = sk.try_verify(&message, &signature.data);

    if res.is_ok() && res.unwrap() {
        SLH_DSA_OK
    } else {
        SLH_DSA_VERIFY_ERROR
    }
}
