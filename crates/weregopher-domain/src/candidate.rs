//! Maintained discovery seeds for the initial application targets.
//!
//! Profiles identify products and known vendor channel labels only. They do not
//! assert that an installation exists, uses Electron, or is compatible.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A product family selected for installed-application discovery.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateTarget {
    /// `OpenAI` Codex desktop workflows.
    Codex,
    /// Nous Research Hermes Agent desktop application.
    HermesAgent,
    /// Discord desktop application.
    Discord,
    /// Microsoft Visual Studio Code desktop application.
    VisualStudioCode,
}

/// A maintained vendor channel label that may seed discovery.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateChannelHint {
    /// Default production channel.
    Stable,
    /// Discord public test build channel.
    Ptb,
    /// Discord canary channel.
    Canary,
    /// Visual Studio Code Insiders channel.
    Insiders,
}

/// Read-only discovery hints for one initial target.
///
/// Channel hints are advisory search inputs. Observed installation metadata is
/// authoritative, and this profile carries no Electron or compatibility claim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CandidateProfile {
    /// Product selected for discovery.
    pub target: CandidateTarget,
    /// Known channel labels worth searching independently.
    pub channel_hints: Vec<CandidateChannelHint>,
}

/// Returns the initial candidate catalog in stable presentation order.
#[must_use]
pub fn initial_candidate_profiles() -> Vec<CandidateProfile> {
    vec![
        CandidateProfile {
            target: CandidateTarget::Codex,
            channel_hints: Vec::new(),
        },
        CandidateProfile {
            target: CandidateTarget::HermesAgent,
            channel_hints: Vec::new(),
        },
        CandidateProfile {
            target: CandidateTarget::Discord,
            channel_hints: vec![
                CandidateChannelHint::Stable,
                CandidateChannelHint::Ptb,
                CandidateChannelHint::Canary,
            ],
        },
        CandidateProfile {
            target: CandidateTarget::VisualStudioCode,
            channel_hints: vec![CandidateChannelHint::Stable, CandidateChannelHint::Insiders],
        },
    ]
}
