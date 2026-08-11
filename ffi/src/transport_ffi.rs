//! C ABI over `clarity_net::RelayTransport` — the relay transport, direct or via
//! Tor. Exposing this through FFI (rather than doing HTTP in Dart) is what lets
//! every platform route over Tor uniformly, since Dart's HTTP stack has no SOCKS
//! support.
//!
//! All network calls here are BLOCKING. The Dart side must invoke them from a
//! background isolate so the UI thread never stalls (see the app wiring).

use std::os::raw::c_char;
use std::ptr;

use clarity_core::identity::Account;
use clarity_net::RelayTransport;

use crate::{as_slice, encode_byte_list, ClarityBuffer};

unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        None
    } else {
        std::ffi::CStr::from_ptr(p).to_str().ok()
    }
}

unsafe fn read_key(p: *const u8) -> Option<[u8; 32]> {
    if p.is_null() {
        return None;
    }
    let mut key = [0u8; 32];
    ptr::copy_nonoverlapping(p, key.as_mut_ptr(), 32);
    Some(key)
}

/// Create a relay transport that talks to `url` directly (clearnet/dev).
///
/// # Safety
/// `url` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn clarity_relay_transport_direct(url: *const c_char) -> *mut RelayTransport {
    match cstr(url) {
        Some(u) => Box::into_raw(Box::new(RelayTransport::direct(u))),
        None => ptr::null_mut(),
    }
}

/// Create a relay transport that routes through a Tor SOCKS5 proxy
/// (`socks_addr`, e.g. `"127.0.0.1:9050"`). `url` may be a `.onion` address.
/// Returns null if the proxy address is invalid.
///
/// # Safety
/// `url` and `socks_addr` must be valid NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn clarity_relay_transport_tor(
    url: *const c_char,
    socks_addr: *const c_char,
) -> *mut RelayTransport {
    match (cstr(url), cstr(socks_addr)) {
        (Some(u), Some(s)) => match RelayTransport::over_tor(u, s) {
            Ok(t) => Box::into_raw(Box::new(t)),
            Err(_) => ptr::null_mut(),
        },
        _ => ptr::null_mut(),
    }
}

/// Release a relay transport handle.
///
/// # Safety
/// `t` must be a handle from this library, or null.
#[no_mangle]
pub unsafe extern "C" fn clarity_relay_transport_free(t: *mut RelayTransport) {
    if !t.is_null() {
        drop(Box::from_raw(t));
    }
}

/// Publish `account`'s base bundle + one-time prekeys to the relay.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `t` and `account` must be valid handles.
#[no_mangle]
pub unsafe extern "C" fn clarity_relay_publish_account(
    t: *const RelayTransport,
    account: *const Account,
) -> i32 {
    let (transport, account) = match (t.as_ref(), account.as_ref()) {
        (Some(t), Some(a)) => (t, a),
        _ => return -1,
    };
    let mut base = account.bundle();
    base.one_time_prekey = None;
    base.one_time_prekey_id = None;
    let one_time = account.one_time_prekey_publics();
    match transport.publish(&base, &one_time) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Fetch a contact's bundle by 32-byte identity. Returns the encoded bundle; an
/// **empty** buffer (non-null ptr, len 0) means "no bundle published"; a **null**
/// ptr means a transport error.
///
/// # Safety
/// `t` valid; `identity` points to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn clarity_relay_fetch_bundle(
    t: *const RelayTransport,
    identity: *const u8,
) -> ClarityBuffer {
    let transport = match t.as_ref() {
        Some(t) => t,
        None => return ClarityBuffer::null(),
    };
    let id = match read_key(identity) {
        Some(id) => id,
        None => return ClarityBuffer::null(),
    };
    match transport.fetch_bundle(&id) {
        Ok(Some(bundle)) => ClarityBuffer::from_vec(bundle.encode()),
        Ok(None) => ClarityBuffer::from_vec(Vec::new()),
        Err(_) => ClarityBuffer::null(),
    }
}

/// Queue an encoded message for `recipient`. Returns 0 on success, -1 on error.
///
/// # Safety
/// `t` valid; `recipient` points to 32 readable bytes; message region readable.
#[no_mangle]
pub unsafe extern "C" fn clarity_relay_send(
    t: *const RelayTransport,
    recipient: *const u8,
    msg: *const u8,
    msg_len: usize,
) -> i32 {
    let transport = match t.as_ref() {
        Some(t) => t,
        None => return -1,
    };
    let recipient = match read_key(recipient) {
        Some(r) => r,
        None => return -1,
    };
    match transport.send(&recipient, as_slice(msg, msg_len)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Poll queued messages for `recipient`. Returns them as an encoded list
/// (see [`crate::encode_byte_list`]); null buffer on error.
///
/// # Safety
/// `t` valid; `recipient` points to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn clarity_relay_poll(
    t: *const RelayTransport,
    recipient: *const u8,
) -> ClarityBuffer {
    let transport = match t.as_ref() {
        Some(t) => t,
        None => return ClarityBuffer::null(),
    };
    let recipient = match read_key(recipient) {
        Some(r) => r,
        None => return ClarityBuffer::null(),
    };
    match transport.poll(&recipient) {
        Ok(messages) => ClarityBuffer::from_vec(encode_byte_list(&messages)),
        Err(_) => ClarityBuffer::null(),
    }
}
