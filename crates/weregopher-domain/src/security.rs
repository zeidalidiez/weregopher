//! Effective execution-security classifications.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The enforcement mechanism that actually constrains an executable component.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveSecurityPosture {
    /// Relevant host effects cross an enforcing Weregopher broker.
    BrokerMediated,
    /// Independently tested operating-system controls constrain direct host access.
    OsContained,
    /// The component can exercise the current Windows user's ordinary authority.
    VendorEquivalentFullTrust,
}
