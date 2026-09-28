//! Data structures for a parsed Sigma rule.

use std::collections::HashMap;

use schema::detection::Severity;
use serde::Deserialize;

/// Sigma rule as loaded from the YAML.
#[derive(Debug, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Required by `validate()` for any rule shipped through
    /// [`crate::SigmaEngine::load_rule`] — `Option` here (rather than a plain
    /// required field) so a missing value is one validation error among several,
    /// not a deserialize failure that would also break every hand-parsed YAML
    /// fixture in unit tests that don't care about metadata.
    #[serde(default)]
    pub severity: Option<Severity>,
    /// Upstream Sigma field name. Required non-empty by `validate()`.
    #[serde(default)]
    pub falsepositives: Vec<String>,
    pub detection: Detection,
}

/// `detection` block of a Sigma rule.
#[derive(Debug, Deserialize)]
pub struct Detection {
    /// Named selections: selection, selection1, filter, etc.
    #[serde(flatten)]
    pub selections: HashMap<String, Selection>,
    /// Condition expression: "selection", "selection1 and selection2", etc.
    pub condition: String,
}

/// A selection = map of field → list of values (OR between values).
/// Example:
/// ```yaml
/// selection:
///   Image|endswith: '\cmd.exe'
///   CommandLine|contains: 'payload'
/// ```
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Selection {
    /// Map of field → values
    FieldMap(HashMap<String, ValueList>),
    /// List of keywords
    Keywords(Vec<String>),
}

/// A Sigma value can be a scalar or a list (implicit OR).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ValueList {
    Single(String),
    Many(Vec<String>),
}

impl ValueList {
    #[must_use]
    pub fn as_slice(&self) -> Vec<&str> {
        match self {
            ValueList::Single(s) => vec![s.as_str()],
            ValueList::Many(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

/// Alert emitted when a Sigma rule matches.
#[derive(Debug, Clone)]
pub struct SigmaAlert {
    pub title: String,
    pub tags: Vec<String>,
    pub description: String,
    pub severity: Severity,
    /// ATT&CK technique ids (`T1234`, `T1234.001`) extracted from `tags`, normalized
    /// to bare uppercase form — issue #74. `tags` keeps the full raw list (tactic
    /// tags included); this is the filtered, structured subset of it.
    pub techniques: Vec<String>,
}
