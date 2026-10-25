use hl_rs_derive::L1Action;
use serde::{Deserialize, Serialize};

/// A single cancel request by client order ID.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CancelByCloidWire {
    /// Asset index
    pub asset: u32,
    /// Client order ID
    pub cloid: String,
}

/// Batch cancel orders by client order ID action.
///
/// Flattened like Python: `{ "type": "cancelByCloid", "cancels": [ ... ] }` (no double `cancels`).
#[derive(Serialize, Deserialize, Debug, Clone, L1Action)]
pub struct CancelByCloid {
    /// Cancel requests
    pub cancels: Vec<CancelByCloidWire>,
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

impl CancelByCloid {
    pub fn new(cancels: Vec<CancelByCloidWire>) -> Self {
        Self {
            cancels,
            fast: false,
            nonce: None,
        }
    }

    /// Set the fast flag. See [`CancelByCloid::fast`].
    pub fn with_fast(mut self, fast: bool) -> Self {
        self.fast = fast;
        self
    }

    pub fn single(asset: u32, cloid: impl Into<String>) -> Self {
        Self::new(vec![CancelByCloidWire {
            asset,
            cloid: cloid.into(),
        }])
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
        let a = CancelByCloid::single(43, "0x0000000000000000000000005e57f011");
        assert_eq!(hx(&a), "82a474797065ad63616e63656c4279436c6f6964a763616e63656c739182a561737365742ba5636c6f6964d92230783030303030303030303030303030303030303030303030303565353766303131", "msgpack drifted for an unset flag");
        assert_eq!(l1(&a), "0xb85278634b9bea0f597a2257c3e0da16cc943c83760a5d1434c90e9d95a7bb1b", "signing hash drifted for an unset flag");
        assert!(!hx(&a).contains("a166"), "`f` must be absent, not false");
    }

    #[test]
    fn set_fast_adds_f_as_true_after_cancels() {
        let hex = hx(&CancelByCloid::single(43, "0x0000000000000000000000005e57f011").with_fast(true));
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
        assert_ne!(l1(&CancelByCloid::single(43, "0x0000000000000000000000005e57f011")), l1(&CancelByCloid::single(43, "0x0000000000000000000000005e57f011").with_fast(true)));
    }

    #[test]
    fn an_action_without_f_deserializes_as_not_fast() {
        let a: CancelByCloid = serde_json::from_str(r#"{"cancels":[{"asset":43,"cloid":"0x01"}]}"#).unwrap();
        assert!(!a.fast);
    }
}
