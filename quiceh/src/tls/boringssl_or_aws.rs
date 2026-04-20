use super::*;

use libc::c_long;

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct CRYPTO_BUFFER {
    _unused: c_void,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub(super) struct SSL_QUIC_METHOD {
    set_read_secret: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            level: crypto::Level,
            cipher: *const SSL_CIPHER,
            secret: *const u8,
            secret_len: usize,
        ) -> c_int,
    >,

    set_write_secret: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            level: crypto::Level,
            cipher: *const SSL_CIPHER,
            secret: *const u8,
            secret_len: usize,
        ) -> c_int,
    >,

    add_handshake_data: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            level: crypto::Level,
            data: *const u8,
            len: usize,
        ) -> c_int,
    >,

    flush_flight: Option<extern "C" fn(ssl: *mut SSL) -> c_int>,

    send_alert: Option<
        extern "C" fn(ssl: *mut SSL, level: crypto::Level, alert: u8) -> c_int,
    >,
}

#[cfg(test)]
#[repr(C)]
#[allow(non_camel_case_types)]
struct SSL_PRIVATE_KEY_METHOD {
    sign: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            out: *mut u8,
            out_len: *mut usize,
            max_out: usize,
            signature_algorithm: u16,
            r#in: *const u8,
            in_len: usize,
        ) -> ssl_private_key_result_t,
    >,

    decrypt: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            out: *mut u8,
            out_len: *mut usize,
            max_out: usize,
            r#in: *const u8,
            in_len: usize,
        ) -> ssl_private_key_result_t,
    >,

    complete: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            out: *mut u8,
            out_len: *mut usize,
            max_out: usize,
        ) -> ssl_private_key_result_t,
    >,
}

pub(super) static QUICHE_STREAM_METHOD: SSL_QUIC_METHOD = SSL_QUIC_METHOD {
    set_read_secret: Some(set_read_secret),
    set_write_secret: Some(set_write_secret),
    add_handshake_data: Some(add_handshake_data),
    flush_flight: Some(flush_flight),
    send_alert: Some(send_alert),
};

impl Context {
    pub fn set_early_data_enabled(&mut self, _enabled: bool) {
        unsafe {
            SSL_CTX_set_early_data_enabled(
                self.as_mut_ptr(),
                i32::from(_enabled),
            );
        }
    }
}

impl Handshake {
    pub fn set_quic_early_data_context(&mut self, context: &[u8]) -> Result<()> {
        map_result(unsafe {
            SSL_set_quic_early_data_context(
                self.as_mut_ptr(),
                context.as_ptr(),
                context.len(),
            )
        })
    }

    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        unsafe {
            let ctx = SSL_get_SSL_CTX(self.as_ptr());

            if ctx.is_null() {
                return Err(Error::TlsFail);
            }

            let session =
                SSL_SESSION_from_bytes(session.as_ptr(), session.len(), ctx);

            if session.is_null() {
                return Err(Error::TlsFail);
            }

            let rc = SSL_set_session(self.as_mut_ptr(), session);
            SSL_SESSION_free(session);

            map_result(rc)
        }
    }

    pub fn reset_early_data_reject(&mut self) {
        unsafe { SSL_reset_early_data_reject(self.as_mut_ptr()) };
    }

    pub fn curve(&self) -> Option<String> {
        let curve = unsafe {
            let curve_id = SSL_get_curve_id(self.as_ptr());
            if curve_id == 0 {
                return None;
            }

            let curve_name = SSL_get_curve_name(curve_id);
            match ffi::CStr::from_ptr(curve_name).to_str() {
                Ok(v) => v,

                Err(_) => return None,
            }
        };

        Some(curve.to_string())
    }

    pub fn sigalg(&self) -> Option<String> {
        let sigalg = unsafe {
            let sigalg_id = SSL_get_peer_signature_algorithm(self.as_ptr());
            if sigalg_id == 0 {
                return None;
            }

            let sigalg_name = SSL_get_signature_algorithm_name(sigalg_id, 1);
            match ffi::CStr::from_ptr(sigalg_name).to_str() {
                Ok(v) => v,

                Err(_) => return None,
            }
        };

        Some(sigalg.to_string())
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        let cert_chain = unsafe {
            let chain =
                map_result_ptr(SSL_get0_peer_certificates(self.as_ptr())).ok()?;

            let num = sk_num(chain);
            if num == 0 {
                return None;
            }

            let mut cert_chain = vec![];
            for i in 0..num {
                let buffer =
                    map_result_ptr(sk_value(chain, i) as *const CRYPTO_BUFFER)
                        .ok()?;

                let out_len = CRYPTO_BUFFER_len(buffer);
                if out_len == 0 {
                    return None;
                }

                let out = CRYPTO_BUFFER_data(buffer);
                let slice = slice::from_raw_parts(out, out_len);

                cert_chain.push(slice);
            }

            cert_chain
        };

        Some(cert_chain)
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        let peer_cert = unsafe {
            let chain =
                map_result_ptr(SSL_get0_peer_certificates(self.as_ptr())).ok()?;
            if sk_num(chain) == 0 {
                return None;
            }

            let buffer =
                map_result_ptr(sk_value(chain, 0) as *const CRYPTO_BUFFER)
                    .ok()?;

            let out_len = CRYPTO_BUFFER_len(buffer);
            if out_len == 0 {
                return None;
            }

            let out = CRYPTO_BUFFER_data(buffer);
            slice::from_raw_parts(out, out_len)
        };

        Some(peer_cert)
    }

    // Only used for testing handling of failure during key signing.
    #[cfg(test)]
    pub fn set_failing_private_key_method(&mut self) {
        extern "C" fn failing_sign(
            _ssl: *mut SSL, _out: *mut u8, _out_len: *mut usize, _max_out: usize,
            _signature_algorithm: u16, _in: *const u8, _in_len: usize,
        ) -> ssl_private_key_result_t {
            ssl_private_key_result_t::ssl_private_key_failure
        }

        extern "C" fn failing_decrypt(
            _ssl: *mut SSL, _out: *mut u8, _out_len: *mut usize, _max_out: usize,
            _in: *const u8, _in_len: usize,
        ) -> ssl_private_key_result_t {
            ssl_private_key_result_t::ssl_private_key_failure
        }

        extern "C" fn failing_complete(
            _ssl: *mut SSL, _out: *mut u8, _out_len: *mut usize, _max_out: usize,
        ) -> ssl_private_key_result_t {
            ssl_private_key_result_t::ssl_private_key_failure
        }

        static QUICHE_PRIVATE_KEY_METHOD: SSL_PRIVATE_KEY_METHOD =
            SSL_PRIVATE_KEY_METHOD {
                decrypt: Some(failing_decrypt),
                sign: Some(failing_sign),
                complete: Some(failing_complete),
            };

        unsafe {
            SSL_set_private_key_method(
                self.as_mut_ptr(),
                &QUICHE_PRIVATE_KEY_METHOD,
            );
        }
    }

    pub fn is_in_early_data(&self) -> bool {
        unsafe { SSL_in_early_data(self.as_ptr()) == 1 }
    }
}

pub(super) fn get_session_bytes(session: *mut SSL_SESSION) -> Result<Vec<u8>> {
    let session_bytes = unsafe {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        if SSL_SESSION_to_bytes(session, &mut out, &mut out_len) == 0 {
            return Err(Error::TlsFail);
        }
        let session_bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        OPENSSL_free(out as *mut c_void);
        session_bytes
    };

    Ok(session_bytes)
}
pub(super) const TLS_ERROR: c_int = 3;

#[cfg(feature = "aws-lc")]
use aws_lc_sys as sys;
#[cfg(feature = "boringssl-boring-crate")]
use boring_sys as sys;

// SSL_METHOD specific for boringssl.
#[inline]
#[allow(non_snake_case)]
pub(super) unsafe fn SSL_CTX_set_tlsext_ticket_keys(
    ctx: *mut SSL_CTX, key: *const u8, key_len: usize,
) -> c_int {
    sys::SSL_CTX_set_tlsext_ticket_keys(ctx as _, key as _, key_len as _) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn SSL_CTX_set_early_data_enabled(ctx: *mut SSL_CTX, enabled: i32) {
    sys::SSL_CTX_set_early_data_enabled(ctx as _, enabled as _);
}

#[inline]
#[allow(non_snake_case)]
pub(super) unsafe fn SSL_CTX_set_session_cache_mode(
    ctx: *mut SSL_CTX, mode: c_int,
) -> c_int {
    sys::SSL_CTX_set_session_cache_mode(ctx as _, mode as _) as _
}

#[inline]
#[allow(non_snake_case)]
pub(super) unsafe fn SSL_get_ex_new_index(
    argl: c_long, argp: *const c_void, unused: *const c_void,
    dup_unused: *const c_void, free_func: *const c_void,
) -> c_int {
    sys::SSL_get_ex_new_index(
        argl as _,
        argp as _,
        std::mem::transmute(unused),
        std::mem::transmute(dup_unused),
        std::mem::transmute(free_func),
    ) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn SSL_get_curve_id(ssl: *const SSL) -> u16 {
    sys::SSL_get_curve_id(ssl as _) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn SSL_get_curve_name(curve: u16) -> *const c_char {
    sys::SSL_get_curve_name(curve as _) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn SSL_get_peer_signature_algorithm(ssl: *const SSL) -> u16 {
    sys::SSL_get_peer_signature_algorithm(ssl as _) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn SSL_get_signature_algorithm_name(
    sigalg: u16, include_curve: i32,
) -> *const c_char {
    sys::SSL_get_signature_algorithm_name(sigalg as _, include_curve as _) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn SSL_get0_peer_certificates(ssl: *const SSL) -> *const STACK_OF {
    sys::SSL_get0_peer_certificates(ssl as _) as _
}

#[inline]
#[allow(non_snake_case)]
pub(super) unsafe fn SSL_set_min_proto_version(
    ssl: *mut SSL, version: u16,
) -> c_int {
    sys::SSL_set_min_proto_version(ssl as _, version as _) as _
}

#[inline]
#[allow(non_snake_case)]
pub(super) unsafe fn SSL_set_max_proto_version(
    ssl: *mut SSL, version: u16,
) -> c_int {
    sys::SSL_set_max_proto_version(ssl as _, version as _) as _
}

#[inline]
#[allow(non_snake_case)]
pub(super) unsafe fn SSL_set_tlsext_host_name(
    ssl: *mut SSL, name: *const c_char,
) -> c_int {
    sys::SSL_set_tlsext_host_name(ssl as _, name as _) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn SSL_set_quic_early_data_context(
    ssl: *mut SSL, context: *const u8, context_len: usize,
) -> c_int {
    sys::SSL_set_quic_early_data_context(ssl as _, context as _, context_len as _)
        as _
}

#[cfg(test)]
#[inline]
#[allow(non_snake_case)]
unsafe fn SSL_set_private_key_method(
    ssl: *mut SSL, key_method: *const SSL_PRIVATE_KEY_METHOD,
) {
    sys::SSL_set_private_key_method(ssl as _, key_method as _);
}

#[inline]
#[allow(non_snake_case)]
unsafe fn SSL_reset_early_data_reject(ssl: *mut SSL) {
    sys::SSL_reset_early_data_reject(ssl as _);
}

#[inline]
#[allow(non_snake_case)]
unsafe fn SSL_in_early_data(ssl: *const SSL) -> c_int {
    sys::SSL_in_early_data(ssl as _) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn SSL_SESSION_to_bytes(
    session: *const SSL_SESSION, out: *mut *mut u8, out_len: *mut usize,
) -> c_int {
    sys::SSL_SESSION_to_bytes(session as _, out as _, out_len as _) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn SSL_SESSION_from_bytes(
    input: *const u8, input_len: usize, ctx: *const SSL_CTX,
) -> *mut SSL_SESSION {
    sys::SSL_SESSION_from_bytes(input as _, input_len as _, ctx as _) as _
}

// STACK_OF
#[cfg(feature = "boringssl-boring-crate")]
#[inline]
#[allow(non_snake_case)]
unsafe fn sk_num(stack: *const STACK_OF) -> usize {
    sys::sk_num(stack as _) as _
}

#[cfg(feature = "boringssl-boring-crate")]
#[inline]
#[allow(non_snake_case)]
unsafe fn sk_value(stack: *const STACK_OF, idx: usize) -> *mut c_void {
    sys::sk_value(stack as _, idx as _) as _
}

#[cfg(all(feature = "aws-lc", not(feature = "boringssl-boring-crate")))]
#[inline]
#[allow(non_snake_case)]
unsafe fn sk_num(stack: *const STACK_OF) -> usize {
    sys::OPENSSL_sk_num(stack as _) as _
}

#[cfg(all(feature = "aws-lc", not(feature = "boringssl-boring-crate")))]
#[inline]
#[allow(non_snake_case)]
unsafe fn sk_value(stack: *const STACK_OF, idx: usize) -> *mut c_void {
    sys::OPENSSL_sk_value(stack as _, idx as _) as _
}

// CRYPTO_BUFFER
#[inline]
#[allow(non_snake_case)]
unsafe fn CRYPTO_BUFFER_len(buffer: *const CRYPTO_BUFFER) -> usize {
    sys::CRYPTO_BUFFER_len(buffer as _) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn CRYPTO_BUFFER_data(buffer: *const CRYPTO_BUFFER) -> *const u8 {
    sys::CRYPTO_BUFFER_data(buffer as _) as _
}
