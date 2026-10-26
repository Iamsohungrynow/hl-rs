use hl_rs_derive::L1Action;
use serde::{Deserialize, Serialize};

use super::OrderWire;

/// Which resting order a modify targets.
///
/// Hyperliquid's `oid` field is a **union**: a numeric order id, or a client order id as a
/// `"0x"`-prefixed 32-hex-character string. Typing it as `u64` alone made the cloid form
/// unrepresentable, which matters because some callers can only ever know the cloid — a contract
/// emitting an intent never learns the oid assigned to it.
///
/// Untagged, so each variant serialises as the bare value it wraps: `Oid(5)` is `5`, exactly as the
/// old `u64` field was, and `Cloid("0x…")` is the string. That keeps the msgpack the signing hash is
/// taken over byte-identical for every existing caller.
///
/// **Measured**, not assumed: msgpacking this structure with a cloid string in `oid` and signing the
/// resulting hash produced a signature Hyperliquid accepted, and it resolved the order by that cloid.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum OrderTarget {
    /// A numeric order id, as Hyperliquid assigned it.
    Oid(u64),
    /// A client order id, `"0x"` followed by 32 hex characters.
    Cloid(String),
}

impl From<u64> for OrderTarget {
    fn from(oid: u64) -> Self {
        Self::Oid(oid)
    }
}

impl OrderTarget {
    /// A cloid rendered the way Hyperliquid expects it: `0x` and 32 hex characters, zero-padded.
    ///
    /// Zero is rendered as-is rather than refused or dropped. A caller naming a cloid of zero has a
    /// bug, and Hyperliquid reporting "no such order" is a better outcome than this silently sending
    /// a different request.
    pub fn cloid(cloid: u128) -> Self {
        Self::Cloid(format!("0x{cloid:032x}"))
    }
}

/// A single modify request.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModifyWire {
    /// The order to modify: a numeric oid, or a cloid string.
    pub oid: OrderTarget,
    /// New order details
    pub order: OrderWire,
}

/// Batch modify orders action.
///
/// JSON and msgpack signing must match the official Python SDK:
/// `{ "type": "batchModify", "modifies": [ { "oid", "order" }, ... ] }`.
///
/// `PAYLOAD_KEY` must **not** be `"modifies"`: the wire struct already has a `modifies` field. Using
/// a different payload key nests the payload as `"modifies": { "modifies": [...] }`, which Hyperliquid
/// rejects with HTTP 422 (`Failed to deserialize the JSON body into the target type`).
#[derive(Serialize, Deserialize, Debug, Clone, L1Action)]
pub struct BatchModify {
    /// Modify requests
    pub modifies: Vec<ModifyWire>,
    #[serde(skip_serializing)]
    pub nonce: Option<u64>,
}

impl BatchModify {
    pub fn new(modifies: Vec<ModifyWire>) -> Self {
        Self {
            modifies,
            nonce: None,
        }
    }

    /// One modify, targeting a numeric order id.
    ///
    /// Takes `impl Into<OrderTarget>` so every existing caller passing a `u64` keeps compiling and
    /// keeps producing the same msgpack.
    pub fn single(oid: impl Into<OrderTarget>, order: OrderWire) -> Self {
        Self::new(vec![ModifyWire {
            oid: oid.into(),
            order,
        }])
    }

    /// One modify, targeting a client order id.
    ///
    /// Spelled out rather than left to `single` so the cloid form is discoverable, and so a caller
    /// cannot pass a cloid where a `u64` was meant and have it silently truncate.
    pub fn single_by_cloid(cloid: u128, order: OrderWire) -> Self {
        Self::new(vec![ModifyWire {
            oid: OrderTarget::cloid(cloid),
            order,
        }])
    }
}
