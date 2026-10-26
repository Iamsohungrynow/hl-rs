use hl_rs_derive::L1Action;
use serde::{Deserialize, Serialize};

/// A single cancel request by order ID.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CancelWire {
    /// Asset index
    pub a: u32,
    /// Order ID to cancel
    pub o: u64,
}

/// Batch cancel orders action.
///
/// Wire shape must match Python: `{ "type": "cancel", "cancels": [ { "a", "o" }, ... ] }`.
/// - `payload_key = "cancels"` incorrectly nests as `"cancels": { "cancels": [...] }` → HTTP 422.
/// - Default derive uses `type: "batchCancel"`; override with `action_type = "cancel"`.
#[derive(Serialize, Deserialize, Debug, Clone, L1Action)]
#[action(action_type = "cancel")]
pub struct BatchCancel {
    /// Cancel requests
    pub cancels: Vec<CancelWire>,
    /// Fast cancel, serialized as `f`.
    ///
    /// Documented for both `cancel` and `cancelByCloid`. It has no effect today: a
    /// future network upgrade will prioritise cancel actions in the mempool if and
    /// only if it is set.
    ///
    /// A `bool` rather than an `Option<bool>` because the protocol has two states,
    /// not three — present and true, or absent. An action hashed with `f: false` is
    /// rejected, which the skip guard prevents from ever being constructed.
    ///
    /// Rejected for trigger orders, so do not set it for a cancel that may name one.
    #[serde(
        rename = "f",
        default,
        skip_serializing_if = "crate::actions::serialization::is_false"
    )]
    pub fast: bool,
    #[serde(skip_serializing)]
    pub nonce: Option<u64>,
}

impl BatchCancel {
    pub fn new(cancels: Vec<CancelWire>) -> Self {
        Self {
            cancels,
            fast: false,
            nonce: None,
        }
    }

    /// Set the fast flag. See [`BatchCancel::fast`].
    pub fn with_fast(mut self, fast: bool) -> Self {
        self.fast = fast;
        self
    }

    pub fn single(asset: u32, oid: u64) -> Self {
        Self::new(vec![CancelWire { a: asset, o: oid }])
    }
}


#[cfg(test)]
mod fast_flag_tests {
    use super::*;
    use crate::actions::serialization::L1ActionWrapper;
    use crate::actions::signing::compute_l1_hash;

    const NONCE: u64 = 1792923662609;

    fn hx<T: serde::Serialize + crate::actions::Action>(a: &T) -> String {
        let w = L1ActionWrapper { action: a };
        rmp_serde::to_vec_named(&w)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn l1<T: serde::Serialize + crate::actions::Action>(a: &T) -> String {
        let w = L1ActionWrapper { action: a };
        compute_l1_hash(&w, NONCE, None, None).unwrap().to_string()
    }

    /// The whole reason the field is a `bool` with a skip guard rather than an
    /// `Option`. These bytes and this hash were captured from the commit before
    /// the field existed, so an unset flag cannot move any existing caller's
    /// signature.
    #[test]
    fn unset_fast_hashes_exactly_as_before_the_field_existed() {
        let a = BatchCancel::single(43, 63638909939);
        assert_eq!(hx(&a), "82a474797065a663616e63656ca763616e63656c739182a1612ba16fcf0000000ed12cb3f3", "msgpack drifted for an unset flag");
        assert_eq!(l1(&a), "0x45e516d7fe1eaafdf469b2340594235b326542667c50eb1dda994e10130e8e75", "signing hash drifted for an unset flag");
        assert!(!hx(&a).contains("a166"), "`f` must be absent, not false");
    }

    #[test]
    fn set_fast_adds_f_as_true_after_cancels() {
        let hex = hx(&BatchCancel::single(43, 63638909939).with_fast(true));
        assert!(hex.starts_with("83"), "expected a 3-entry map, got {hex}");
        assert!(hex.contains("a166c3"), "expected `f: true`, got {hex}");
        let cancels = hex.find("a763616e63656c73").expect("cancels key");
        let flag = hex.find("a166c3").expect("f key");
        assert!(
            cancels < flag,
            "`f` must follow `cancels`, since msgpack key order follows \
             declaration order and the hash depends on it"
        );
    }

    #[test]
    fn set_fast_changes_the_hash() {
        assert_ne!(l1(&BatchCancel::single(43, 63638909939)), l1(&BatchCancel::single(43, 63638909939).with_fast(true)));
    }

    #[test]
    fn an_action_without_f_deserializes_as_not_fast() {
        let a: BatchCancel = serde_json::from_str(r#"{"cancels":[{"a":43,"o":1}]}"#).unwrap();
        assert!(!a.fast);
    }
}
