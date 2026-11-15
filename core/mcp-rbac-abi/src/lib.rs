//! Raw C ABI over mcp_rbac_core::engine for hosts without wasm-bindgen (Go via wazero; any WASI-less wasm host).
//!
//! Memory protocol (all lengths in bytes, strings UTF-8):
//! * `mrc_alloc(len) -> ptr` gives the host a buffer to write input into; the host frees it with `mrc_free(ptr, len)`.
//! * Calls return a packed `u64` = `(ptr << 32) | len` of a result buffer owned by the host after return
//!   (free with `mrc_free`). Engines are referred to by `u32` handles (0 = error; `mrc_last_error` has the message).
//!
//! `unsafe` is confined to the three pointer conversions in this file (the FFI boundary); the core forbids it.
#![deny(unsafe_op_in_unsafe_fn)]
// Pointers cross the boundary as u32, which is only sound on wasm32: the ABI is not compiled for other targets.
#![cfg(target_arch = "wasm32")]

use mcp_rbac_core::engine::{redact_json, yaml_doc_json, Engine};
use std::cell::RefCell;

thread_local! {
    static ENGINES: RefCell<Vec<Option<Engine>>> = const { RefCell::new(Vec::new()) };
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn give(s: String) -> u64 {
    let b: Box<[u8]> = s.into_bytes().into_boxed_slice();
    let len = b.len() as u64;
    let ptr = Box::into_raw(b) as *mut u8 as usize as u64;
    (ptr << 32) | len
}

/// # Safety
/// `ptr`/`len` must describe a live buffer previously returned by `mrc_alloc` (or a result buffer) and written by the host.
unsafe fn read<'a>(ptr: u32, len: u32) -> &'a [u8] {
    if len == 0 { return &[] }
    // SAFETY: the host guarantees the region is one of our allocations of at least `len` bytes (protocol above).
    unsafe { std::slice::from_raw_parts(ptr as usize as *const u8, len as usize) }
}

fn text(b: &[u8]) -> Result<&str, String> { std::str::from_utf8(b).map_err(|_| "input is not valid UTF-8".to_string()) }

#[no_mangle]
pub extern "C" fn mrc_alloc(len: u32) -> u32 {
    let b: Box<[u8]> = vec![0u8; len as usize].into_boxed_slice();
    Box::into_raw(b) as *mut u8 as usize as u32
}

/// # Safety
/// `ptr`/`len` must come from `mrc_alloc` or a packed result, and be freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn mrc_free(ptr: u32, len: u32) {
    if ptr == 0 { return }
    // SAFETY: reconstructs the Box<[u8]> leaked by mrc_alloc/give with the same length (len == capacity).
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr as usize as *mut u8, len as usize)) });
}

fn set_err(e: String) -> u32 { LAST_ERROR.with(|l| *l.borrow_mut() = e); 0 }

/// Load a policy (`json_only` = 1: JSON text only). Returns a handle, or 0 (see `mrc_last_error`).
/// # Safety
/// See the memory protocol.
#[no_mangle]
pub unsafe extern "C" fn mrc_engine_new(ptr: u32, len: u32, json_only: u32) -> u32 {
    let src = match text(unsafe { read(ptr, len) }) { Ok(s) => s, Err(e) => return set_err(e) };
    let e = if json_only == 1 { Engine::new_json(src) } else { Engine::new(src) };
    match e {
        Ok(e) => ENGINES.with(|v| {
            let mut v = v.borrow_mut();
            if let Some(i) = v.iter().position(Option::is_none) { v[i] = Some(e); (i + 1) as u32 } else { v.push(Some(e)); v.len() as u32 }
        }),
        Err(m) => set_err(m),
    }
}

#[no_mangle]
pub extern "C" fn mrc_engine_free(h: u32) {
    ENGINES.with(|v| { if let Some(slot) = v.borrow_mut().get_mut((h as usize).wrapping_sub(1)) { *slot = None } });
}

#[no_mangle]
pub extern "C" fn mrc_last_error() -> u64 { give(LAST_ERROR.with(|l| l.borrow().clone())) }

pub const OP_DECIDE: u32 = 1;
pub const OP_VISIBLE: u32 = 2;
pub const OP_AUTHORIZE: u32 = 3;
pub const OP_AUTHORIZE_APPROVED: u32 = 4;
pub const OP_REDACT: u32 = 5;
pub const OP_WARNINGS: u32 = 6;
pub const OP_CHECK: u32 = 7;
pub const OP_YAML_TO_JSON: u32 = 8;
pub const OP_VERSION: u32 = 9;
/// Post-call cost accounting: p1 = decision JSON, p2 = CallToolResult JSON.
pub const OP_ACCOUNT: u32 = 10;
/// Pure cost read: p1 = `{"decision":…,"result":…}` (handle ignored).
pub const OP_COST: u32 = 11;
/// YAML → JSON preserving mapping order (`{"doc":…}` / `{"error":"yaml_invalid"}`); used by host-side pack resolution,
/// where `semantics.tools` order is first-match precedence. OP_YAML_TO_JSON stays canonical (sorted) for conformance.
pub const OP_YAML_TO_JSON_ORDERED: u32 = 12;

/// One entry point for every string operation. `h` is ignored by CHECK / YAML_TO_JSON / VERSION.
/// Errors (unknown handle, bad UTF-8, unknown op) come back as `{"error":"abi:<what>"}`.
/// # Safety
/// See the memory protocol.
#[no_mangle]
pub unsafe extern "C" fn mrc_call(h: u32, op: u32, p1: u32, l1: u32, p2: u32, l2: u32, now_ms: f64) -> u64 {
    let a = match text(unsafe { read(p1, l1) }) { Ok(s) => s, Err(_) => return give(r#"{"error":"abi:utf8"}"#.into()) };
    let b = match text(unsafe { read(p2, l2) }) { Ok(s) => s, Err(_) => return give(r#"{"error":"abi:utf8"}"#.into()) };
    let out = match op {
        OP_CHECK => mcp_rbac_core::check_policy(a),
        OP_YAML_TO_JSON => yaml_doc_json(a),
        OP_VERSION => mcp_rbac_core::VERSION.to_string(),
        OP_REDACT => redact_json(a, b),
        OP_COST => mcp_rbac_core::semantics::cost_json(a),
        OP_YAML_TO_JSON_ORDERED => match mcp_rbac_core::yaml::load(a) {
            Ok(d) => format!("{{\"doc\":{}}}", serde_json::to_string(&d).unwrap_or_else(|_| "null".into())),
            Err(_) => r#"{"error":"yaml_invalid"}"#.into(),
        },
        _ => ENGINES.with(|v| {
            let v = v.borrow();
            let Some(Some(e)) = v.get((h as usize).wrapping_sub(1)) else { return r#"{"error":"abi:handle"}"#.to_string() };
            match op {
                OP_DECIDE => e.decide(a),
                OP_VISIBLE => e.visible(a),
                OP_AUTHORIZE => e.authorize(a, now_ms),
                OP_AUTHORIZE_APPROVED => e.authorize_approved(a, now_ms),
                OP_WARNINGS => e.warnings(),
                OP_ACCOUNT => e.account(a, b, now_ms),
                _ => r#"{"error":"abi:op"}"#.to_string(),
            }
        }),
    };
    give(out)
}
