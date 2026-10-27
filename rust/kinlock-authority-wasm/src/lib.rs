//! The Kinlock Authority core as a WebAssembly module.
//!
//! The host (the Go gateway, through wazero) talks to it with one JSON call:
//!
//! 1. `kinlock_input(len) -> ptr`: reserve `len` bytes and get where to write the request.
//! 2. write `{"op": ..., "input": ...}` as UTF-8 at `ptr`.
//! 3. `kinlock_run(len) -> out_len`: decide; the reply is JSON, the same as `conformance::run`.
//! 4. `kinlock_output() -> ptr`: read `out_len` bytes there.
//!
//! No unsafe blocks: the buffers live in Rust and only their addresses are handed out.
//! `#[no_mangle]` is the one thing the `unsafe_code` lint flags, so only the exports allow it.
//! A panic aborts the module (a trap); the gateway treats any trap as a refusal.

use std::cell::RefCell;

use serde_json::{json, Value};

thread_local! {
    static INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Decide one request given as JSON bytes. The same function the exports call, usable natively.
pub fn handle(request: &[u8]) -> Vec<u8> {
    let reply = match serde_json::from_slice::<Value>(request) {
        Ok(req) => kinlock_authority_core::conformance::run_request(&req),
        Err(e) => json!({"error": format!("the request is not valid JSON: {e}")}),
    };
    reply.to_string().into_bytes()
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn kinlock_input(len: u32) -> u32 {
    INPUT.with(|b| {
        let mut b = b.borrow_mut();
        b.clear();
        b.resize(len as usize, 0);
        b.as_mut_ptr() as usize as u32
    })
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn kinlock_run(len: u32) -> u32 {
    let out = INPUT.with(|b| {
        let b = b.borrow();
        let n = (len as usize).min(b.len());
        handle(&b[..n])
    });
    OUTPUT.with(|o| {
        let mut o = o.borrow_mut();
        *o = out;
        o.len() as u32
    })
}

#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn kinlock_output() -> u32 {
    OUTPUT.with(|o| o.borrow().as_ptr() as usize as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_json_call() {
        let out = handle(br#"{"op":"canonical","input":{"value":{"b":1,"a":[true,null]}}}"#);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["canonical"], r#"{"a":[true,null],"b":1}"#);
        let bad: Value = serde_json::from_slice(&handle(b"not json")).unwrap();
        assert!(bad["error"]
            .as_str()
            .unwrap()
            .starts_with("the request is not valid JSON"));
    }
}
