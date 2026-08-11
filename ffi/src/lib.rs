//! # clarity-ffi
//!
//! A small, stable C ABI over [`clarity_core`], so the cross-platform Flutter
//! app (and any other host language) can drive the protocol through `dart:ffi`.
//!
//! ## Memory ownership rules (read these)
//!
//! * Opaque handles (`*mut Account`, `*mut Session`) are created by the
//!   `*_generate` / `*_initiate` / `*_respond` / `*_deserialize` functions and
//!   **must** be released with the matching `*_free`.
//! * Byte buffers are returned as [`ClarityBuffer`]; free every non-null buffer
//!   with [`clarity_buffer_free`]. A returned buffer with a null `ptr` signals an
//!   error.
//! * C strings are freed with [`clarity_string_free`].
//!
//! Everything here is `unsafe` at the boundary by nature; the unsafe surface is
//! kept tiny and all real logic lives in the safe `clarity_core` crate.

use std::os::raw::c_char;
use std::ptr;

use clarity_core::identity::Account;
use clarity_core::{safety_number, Message, PreKeyBundle, Session};

/// An owned byte buffer handed across the FFI boundary.
///
/// A buffer with `ptr == null` means "operation failed". Free with
/// [`clarity_buffer_free`].
#[repr(C)]
pub struct ClarityBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

impl ClarityBuffer {
    fn from_vec(v: Vec<u8>) -> ClarityBuffer {
        let mut boxed = v.into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        let len = boxed.len();
        std::mem::forget(boxed);
        ClarityBuffer { ptr, len }
    }

    fn null() -> ClarityBuffer {
        ClarityBuffer {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }
}

/// Free a buffer returned by any function in this library.
///
/// # Safety
/// `buf` must have been produced by this library and not already freed.
#[no_mangle]
pub unsafe extern "C" fn clarity_buffer_free(buf: ClarityBuffer) {
    if !buf.ptr.is_null() {
        drop(Box::from_raw(std::slice::from_raw_parts_mut(buf.ptr, buf.len)));
    }
}

/// Free a C string returned by this library.
///
/// # Safety
/// `s` must have been produced by this library and not already freed.
#[no_mangle]
pub unsafe extern "C" fn clarity_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(std::ffi::CString::from_raw(s));
    }
}

unsafe fn as_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

// --- Account ---------------------------------------------------------------

/// Create a fresh account with a default pool of one-time prekeys.
#[no_mangle]
pub extern "C" fn clarity_account_generate() -> *mut Account {
    Box::into_raw(Box::new(Account::generate()))
}

/// Release an account handle.
///
/// # Safety
/// `acct` must be a handle from this library, or null.
#[no_mangle]
pub unsafe extern "C" fn clarity_account_free(acct: *mut Account) {
    if !acct.is_null() {
        drop(Box::from_raw(acct));
    }
}

/// Serialize the full secret account state for encrypted-at-rest storage.
///
/// # Safety
/// `acct` must be a valid account handle.
#[no_mangle]
pub unsafe extern "C" fn clarity_account_serialize(acct: *const Account) -> ClarityBuffer {
    match acct.as_ref() {
        Some(a) => ClarityBuffer::from_vec(a.to_bytes()),
        None => ClarityBuffer::null(),
    }
}

/// Restore an account from bytes produced by [`clarity_account_serialize`].
/// Returns null on failure.
///
/// # Safety
/// `ptr`/`len` must describe a valid readable region.
#[no_mangle]
pub unsafe extern "C" fn clarity_account_deserialize(ptr: *const u8, len: usize) -> *mut Account {
    match Account::from_bytes(as_slice(ptr, len)) {
        Ok(a) => Box::into_raw(Box::new(a)),
        Err(_) => ptr::null_mut(),
    }
}

/// Write the 32-byte Ed25519 identity public key into `out` (must hold 32 bytes).
///
/// # Safety
/// `acct` must be valid; `out` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn clarity_account_identity_public(acct: *const Account, out: *mut u8) {
    if let (Some(a), false) = (acct.as_ref(), out.is_null()) {
        let id = a.identity_public();
        ptr::copy_nonoverlapping(id.as_ptr(), out, 32);
    }
}

/// Encode this account's base prekey bundle (no one-time prekey attached), for
/// upload to a relay's prekey directory.
///
/// # Safety
/// `acct` must be valid.
#[no_mangle]
pub unsafe extern "C" fn clarity_account_bundle_base(acct: *const Account) -> ClarityBuffer {
    match acct.as_ref() {
        Some(a) => {
            let mut bundle = a.bundle();
            bundle.one_time_prekey = None;
            bundle.one_time_prekey_id = None;
            ClarityBuffer::from_vec(bundle.encode())
        }
        None => ClarityBuffer::null(),
    }
}

/// Return this account's one-time prekey public keys as a JSON array
/// `[{"id":<u32>,"public":"<base64>"}]`, for upload to a relay.
///
/// # Safety
/// `acct` must be valid.
#[no_mangle]
pub unsafe extern "C" fn clarity_account_one_time_publics(acct: *const Account) -> ClarityBuffer {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    match acct.as_ref() {
        Some(a) => {
            let entries: Vec<serde_json::Value> = a
                .one_time_prekey_publics()
                .into_iter()
                .map(|(id, public)| {
                    serde_json::json!({ "id": id, "public": STANDARD.encode(public) })
                })
                .collect();
            let json = serde_json::Value::Array(entries).to_string();
            ClarityBuffer::from_vec(json.into_bytes())
        }
        None => ClarityBuffer::null(),
    }
}

// --- Session ---------------------------------------------------------------

/// Begin a session with a contact, given their verified prekey bundle bytes.
/// Returns null if the bundle is malformed or its signatures fail.
///
/// # Safety
/// `acct` must be valid; `bundle_ptr`/`bundle_len` must describe a readable
/// region.
#[no_mangle]
pub unsafe extern "C" fn clarity_session_initiate(
    acct: *const Account,
    bundle_ptr: *const u8,
    bundle_len: usize,
) -> *mut Session {
    let account = match acct.as_ref() {
        Some(a) => a,
        None => return ptr::null_mut(),
    };
    let bundle = match PreKeyBundle::decode(as_slice(bundle_ptr, bundle_len)) {
        Ok(b) => b,
        Err(_) => return ptr::null_mut(),
    };
    match Session::initiate(account, &bundle) {
        Ok(s) => Box::into_raw(Box::new(s)),
        Err(_) => ptr::null_mut(),
    }
}

/// Accept an inbound first message, establishing a session. On success returns
/// a session handle and writes the first plaintext into `out_plaintext`. On
/// failure returns null and leaves `out_plaintext` as a null buffer.
///
/// # Safety
/// `acct` must be a valid, mutable account handle; the message region must be
/// readable; `out_plaintext` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn clarity_session_respond(
    acct: *mut Account,
    msg_ptr: *const u8,
    msg_len: usize,
    out_plaintext: *mut ClarityBuffer,
) -> *mut Session {
    if !out_plaintext.is_null() {
        *out_plaintext = ClarityBuffer::null();
    }
    let account = match acct.as_mut() {
        Some(a) => a,
        None => return ptr::null_mut(),
    };
    let message = match Message::decode(as_slice(msg_ptr, msg_len)) {
        Ok(m) => m,
        Err(_) => return ptr::null_mut(),
    };
    match Session::respond(account, &message) {
        Ok((session, plaintext)) => {
            if !out_plaintext.is_null() {
                *out_plaintext = ClarityBuffer::from_vec(plaintext);
            }
            Box::into_raw(Box::new(session))
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Encrypt a plaintext message. Returns encoded [`Message`] bytes, or a null
/// buffer on error.
///
/// # Safety
/// `sess` must be a valid session handle; the plaintext region must be readable.
#[no_mangle]
pub unsafe extern "C" fn clarity_session_encrypt(
    sess: *mut Session,
    pt_ptr: *const u8,
    pt_len: usize,
) -> ClarityBuffer {
    match sess.as_mut() {
        Some(s) => match s.encrypt(as_slice(pt_ptr, pt_len)) {
            Ok(msg) => ClarityBuffer::from_vec(msg.encode()),
            Err(_) => ClarityBuffer::null(),
        },
        None => ClarityBuffer::null(),
    }
}

/// Decrypt an incoming encoded [`Message`]. Returns plaintext bytes, or a null
/// buffer on error.
///
/// # Safety
/// `sess` must be a valid session handle; the message region must be readable.
#[no_mangle]
pub unsafe extern "C" fn clarity_session_decrypt(
    sess: *mut Session,
    msg_ptr: *const u8,
    msg_len: usize,
) -> ClarityBuffer {
    let session = match sess.as_mut() {
        Some(s) => s,
        None => return ClarityBuffer::null(),
    };
    let message = match Message::decode(as_slice(msg_ptr, msg_len)) {
        Ok(m) => m,
        Err(_) => return ClarityBuffer::null(),
    };
    match session.decrypt(&message) {
        Ok(pt) => ClarityBuffer::from_vec(pt),
        Err(_) => ClarityBuffer::null(),
    }
}

/// Release a session handle.
///
/// # Safety
/// `sess` must be a session handle from this library, or null.
#[no_mangle]
pub unsafe extern "C" fn clarity_session_free(sess: *mut Session) {
    if !sess.is_null() {
        drop(Box::from_raw(sess));
    }
}

// --- Safety numbers --------------------------------------------------------

/// Compute the human-comparable safety number for two 32-byte identity keys.
/// Returns a NUL-terminated C string (free with [`clarity_string_free`]), or
/// null on error.
///
/// # Safety
/// `id_a` and `id_b` must each point to at least 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn clarity_safety_number(id_a: *const u8, id_b: *const u8) -> *mut c_char {
    if id_a.is_null() || id_b.is_null() {
        return ptr::null_mut();
    }
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    ptr::copy_nonoverlapping(id_a, a.as_mut_ptr(), 32);
    ptr::copy_nonoverlapping(id_b, b.as_mut_ptr(), 32);
    match std::ffi::CString::new(safety_number(&a, &b)) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests;
