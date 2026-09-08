use std::collections::BTreeMap as Map;
use std::fmt;

/// Deterministic limits for ambiguous blank-node canonicalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizationLimits {
    /// Shared candidate-permutation budget for one dataset (default: 100,000).
    pub max_permutations: usize,
    /// Maximum n-degree call depth, including the initial call (default: 64).
    pub max_recursion_depth: usize,
}

impl Default for NormalizationLimits {
    fn default() -> Self {
        Self {
            max_permutations: 100_000,
            max_recursion_depth: 64,
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum NormalizationError {
    #[error("RDF canonicalization permutation limit exceeded")]
    WorkLimitExceeded,
    #[error("RDF canonicalization recursion limit exceeded")]
    RecursionLimitExceeded,
    #[error("RDF canonicalization could not choose an identifier issuer")]
    MissingChosenIssuer,
}

/// Work performed by a successful normalization.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NormalizationStats {
    pub first_degree_hashes: usize,
    pub n_degree_calls: usize,
    pub permutations: usize,
    /// The deepest n-degree call, counting the initial call as depth one.
    pub max_recursion_depth: usize,
}

use rdf_types::BlankId;
use rdf_types::QuadRef;
use rdf_types::{BlankIdBuf, Quad};

use ssi_crypto::hashes::sha256::sha256;

use crate::rdf::IntoNQuads;
use crate::rdf::NQuadsStatement;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlankIdPosition {
    Subject,
    Object,
    Graph,
}

impl BlankIdPosition {
    pub fn into_char(self) -> char {
        match self {
            Self::Subject => 's',
            Self::Object => 'o',
            Self::Graph => 'g',
        }
    }
}

impl From<BlankIdPosition> for char {
    fn from(p: BlankIdPosition) -> Self {
        p.into_char()
    }
}

impl fmt::Display for BlankIdPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.into_char().fmt(f)
    }
}

pub trait BlankNodeComponents<'a> {
    fn blank_node_components(&self) -> Vec<&'a BlankId>;

    fn blank_node_components_with_position(&self) -> Vec<(&'a BlankId, BlankIdPosition)>;
}

pub trait BlankNodeComponentsMut {
    fn blank_node_components_mut(&mut self) -> Vec<&mut BlankIdBuf>;
}

impl<'a> BlankNodeComponents<'a> for QuadRef<'a> {
    fn blank_node_components(&self) -> Vec<&'a BlankId> {
        self.blank_node_components_with_position()
            .into_iter()
            .map(|(label, _position)| label)
            .collect()
    }

    fn blank_node_components_with_position(&self) -> Vec<(&'a BlankId, BlankIdPosition)> {
        let mut labels = Vec::new();
        if let rdf_types::Subject::Blank(label) = self.0 {
            labels.push((label, BlankIdPosition::Subject))
        }
        if let rdf_types::Object::Blank(label) = self.2 {
            labels.push((label, BlankIdPosition::Object))
        }
        if let Some(rdf_types::GraphLabel::Blank(label)) = self.3 {
            labels.push((label, BlankIdPosition::Graph))
        }
        labels
    }
}

impl BlankNodeComponentsMut for Quad {
    fn blank_node_components_mut(&mut self) -> Vec<&mut BlankIdBuf> {
        let mut labels: Vec<&mut BlankIdBuf> = Vec::new();
        if let rdf_types::Subject::Blank(label) = &mut self.0 {
            labels.push(label)
        }
        if let rdf_types::Object::Blank(label) = &mut self.2 {
            labels.push(label)
        }
        if let Some(rdf_types::GraphLabel::Blank(label)) = &mut self.3 {
            labels.push(label)
        }
        labels
    }
}

/// <https://www.w3.org/TR/rdf-canon/#normalization-state>
#[derive(Debug, Clone)]
struct NormalizationState<'a> {
    blank_node_to_quads: Map<&'a BlankId, Vec<QuadRef<'a>>>,
    // These hashes depend only on the original, immutable dataset, not on issuers.
    first_degree_hashes: Map<&'a BlankId, String>,
    canonical_issuer: IdentifierIssuer,
    limits: NormalizationLimits,
    stats: NormalizationStats,
}

/// <https://www.w3.org/TR/rdf-canon/#dfn-identifier-issuer>  
/// <https://www.w3.org/TR/rdf-canon/#blank-node-identifier-issuer-state>
#[derive(Debug, Clone)]
pub struct IdentifierIssuer {
    pub identifier_prefix: String,
    pub identifier_counter: u64,
    issued_identifiers_list: Vec<(BlankIdBuf, BlankIdBuf)>,
    issued_identifiers_index: Map<BlankIdBuf, usize>,
}

impl IdentifierIssuer {
    pub fn new(prefix: String) -> Self {
        Self {
            identifier_prefix: prefix,
            identifier_counter: 0,
            issued_identifiers_list: Vec::new(),
            issued_identifiers_index: Map::new(),
        }
    }
    pub fn find_issued_identifier(&self, existing_identifier: &BlankId) -> Option<&BlankId> {
        self.issued_identifiers_index
            .get(existing_identifier)
            .map(|&index| self.issued_identifiers_list[index].0.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct HashNDegreeQuadsOutput {
    pub hash: String,
    pub issuer: IdentifierIssuer,
}

fn digest_to_lowerhex(digest: &[u8]) -> String {
    digest
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}

/// <https://www.w3.org/TR/rdf-canon/#hash-1d-quads>
fn hash_first_degree_quads(
    quads: &[QuadRef<'_>],
    reference_blank_node_identifier: &BlankId,
) -> String {
    // https://www.w3.org/TR/rdf-canon/#algorithm-1
    // 1
    let mut nquads: Vec<String> = Vec::new();
    // 2
    for quad in quads {
        // 3
        let mut quad: Quad = quad.into_owned();
        for label in quad.blank_node_components_mut() {
            *label = if label == reference_blank_node_identifier {
                BlankIdBuf::from_suffix("a").unwrap()
            } else {
                BlankIdBuf::from_suffix("z").unwrap()
            };
        }
        let nquad = NQuadsStatement(&quad).to_string();
        nquads.push(nquad);
    }
    // 4
    nquads.sort();
    // 5
    let joined_nquads = nquads.join("");
    let nquads_digest = sha256(joined_nquads.as_bytes());
    digest_to_lowerhex(&nquads_digest)
}

/// <https://www.w3.org/TR/rdf-canon/>
///
/// Uses the default limits: 100,000 candidate permutations and n-degree depth 64.
/// Exhausting either limit returns an error before any canonical output is exposed.
pub fn normalize<'a, Q: IntoIterator<Item = QuadRef<'a>>>(
    quads: Q,
) -> Result<NormalizedQuads<'a, Q::IntoIter>, NormalizationError>
where
    Q::IntoIter: Clone,
{
    normalize_with_limits(quads, NormalizationLimits::default())
}

/// Canonicalizes a dataset with a shared permutation budget for the entire operation.
///
/// Limits bound ambiguous-node search, not JSON-LD expansion or input size.
/// A limit error must be propagated; it is not permission to sign partial output.
pub fn normalize_with_limits<'a, Q: IntoIterator<Item = QuadRef<'a>>>(
    quads: Q,
    limits: NormalizationLimits,
) -> Result<NormalizedQuads<'a, Q::IntoIter>, NormalizationError>
where
    Q::IntoIter: Clone,
{
    let quads = quads.into_iter();
    let mut normalization_state = NormalizationState {
        blank_node_to_quads: Map::new(),
        first_degree_hashes: Map::new(),
        canonical_issuer: IdentifierIssuer::new("_:c14n".to_string()),
        limits,
        stats: NormalizationStats::default(),
    };
    for quad in quads.clone() {
        let mut identifiers = quad.blank_node_components();
        // A quad belongs to a node's set once, even if the node occupies several positions.
        identifiers.sort_unstable();
        identifiers.dedup();
        for identifier in identifiers {
            normalization_state
                .blank_node_to_quads
                .entry(identifier)
                .or_insert_with(Vec::new)
                .push(quad);
        }
    }

    let mut hash_to_blank_nodes: Map<String, Vec<&BlankId>> = Map::new();
    for (&identifier, related_quads) in &normalization_state.blank_node_to_quads {
        let hash = hash_first_degree_quads(related_quads, identifier);
        normalization_state.stats.first_degree_hashes += 1;
        normalization_state
            .first_degree_hashes
            .insert(identifier, hash.clone());
        hash_to_blank_nodes
            .entry(hash)
            .or_insert_with(Vec::new)
            .push(identifier);
    }
    // First-degree hashes never change when identifiers are issued, so one pass suffices.
    for identifier_list in hash_to_blank_nodes.values() {
        if identifier_list.len() == 1 {
            issue_identifier(
                &mut normalization_state.canonical_issuer,
                identifier_list[0],
            );
        }
    }

    for identifier_list in hash_to_blank_nodes.values().filter(|ids| ids.len() > 1) {
        let mut hash_path_list = Vec::new();
        for &identifier in identifier_list {
            if normalization_state
                .canonical_issuer
                .find_issued_identifier(identifier)
                .is_some()
            {
                continue;
            }
            let mut temporary_issuer = IdentifierIssuer::new("_:b".to_string());
            issue_identifier(&mut temporary_issuer, identifier);
            hash_path_list.push(hash_n_degree_quads(
                &mut normalization_state,
                identifier,
                temporary_issuer,
                1,
            )?);
        }
        hash_path_list.sort_by(|a, b| a.hash.cmp(&b.hash));
        for result in hash_path_list {
            for (_, existing_identifier) in result.issuer.issued_identifiers_list {
                issue_identifier(
                    &mut normalization_state.canonical_issuer,
                    &existing_identifier,
                );
            }
        }
    }

    Ok(NormalizedQuads {
        quads,
        normalization_state,
    })
}

pub struct NormalizedQuads<'a, Q> {
    quads: Q,
    normalization_state: NormalizationState<'a>,
}

impl<'a, Q> NormalizedQuads<'a, Q> {
    /// Returns aggregate work counters without exposing document contents.
    pub fn stats(&self) -> &NormalizationStats {
        &self.normalization_state.stats
    }
}

impl<'a, Q: Iterator<Item = QuadRef<'a>>> NormalizedQuads<'a, Q> {
    pub fn into_nquads(self) -> String {
        IntoNQuads::into_nquads(self)
    }
}

impl<'a, Q: Iterator<Item = QuadRef<'a>>> Iterator for NormalizedQuads<'a, Q> {
    type Item = Quad;

    fn next(&mut self) -> Option<Self::Item> {
        self.quads.next().map(|quad| {
            // 7.1
            let mut quad_copy = quad.into_owned();
            for label in quad_copy.blank_node_components_mut() {
                let canonical_identifier = self
                    .normalization_state
                    .canonical_issuer
                    .find_issued_identifier(label)
                    .unwrap();
                *label = canonical_identifier.to_owned();
            }
            // 7.2
            quad_copy
        })
    }
}

/// <https://www.w3.org/TR/rdf-canon/#issue-identifier-algorithm>
pub fn issue_identifier(
    identifier_issuer: &mut IdentifierIssuer,
    existing_identifier: &BlankId,
) -> BlankIdBuf {
    // https://www.w3.org/TR/rdf-canon/#algorithm-0
    // 1
    if let Some(id) = identifier_issuer.find_issued_identifier(existing_identifier) {
        return id.to_owned();
    }
    // 2
    let issued_identifier = BlankIdBuf::new(
        identifier_issuer.identifier_prefix.to_owned()
            + &identifier_issuer.identifier_counter.to_string(),
    )
    .unwrap();
    // 3
    identifier_issuer.issued_identifiers_index.insert(
        existing_identifier.to_owned(),
        identifier_issuer.issued_identifiers_list.len(),
    );
    identifier_issuer
        .issued_identifiers_list
        .push((issued_identifier.clone(), existing_identifier.to_owned()));
    // 4
    identifier_issuer.identifier_counter += 1;
    // 5
    issued_identifier
}

/// Advances a sorted multiset in place, visiting each distinct permutation once.
fn next_permutation<T: Ord>(values: &mut [T]) -> bool {
    let Some(pivot) = (1..values.len()).rev().find(|&i| values[i - 1] < values[i]) else {
        return false;
    };
    let mut successor = values.len() - 1;
    while values[successor] <= values[pivot - 1] {
        successor -= 1;
    }
    values.swap(pivot - 1, successor);
    values[pivot..].reverse();
    true
}

/// <https://www.w3.org/TR/rdf-canon/#hash-n-degree-quads>
fn hash_n_degree_quads<'a>(
    normalization_state: &mut NormalizationState<'a>,
    identifier: &BlankId,
    mut issuer: IdentifierIssuer,
    depth: usize,
) -> Result<HashNDegreeQuadsOutput, NormalizationError> {
    if depth > normalization_state.limits.max_recursion_depth {
        return Err(NormalizationError::RecursionLimitExceeded);
    }
    normalization_state.stats.n_degree_calls += 1;
    normalization_state.stats.max_recursion_depth =
        normalization_state.stats.max_recursion_depth.max(depth);

    let mut hash_to_related_blank_nodes: Map<String, Vec<&'a BlankId>> = Map::new();
    if let Some(quads) = normalization_state.blank_node_to_quads.get(identifier) {
        for &quad in quads {
            for (component, position) in quad.blank_node_components_with_position() {
                if component != identifier {
                    let hash = hash_related_blank_node(
                        normalization_state,
                        component,
                        quad,
                        &issuer,
                        position,
                    );
                    hash_to_related_blank_nodes
                        .entry(hash)
                        .or_insert_with(Vec::new)
                        .push(component);
                }
            }
        }
    }

    let mut data_to_hash = String::new();
    for (related_hash, mut blank_node_list) in hash_to_related_blank_nodes {
        data_to_hash.push_str(&related_hash);
        let mut chosen_path = String::new();
        let mut chosen_issuer = None;
        // Keep repeated occurrences in each candidate, but never enumerate identical candidates.
        blank_node_list.sort_unstable();
        let mut first_permutation = true;
        'permutations: while first_permutation || next_permutation(&mut blank_node_list) {
            first_permutation = false;
            if normalization_state.stats.permutations >= normalization_state.limits.max_permutations
            {
                return Err(NormalizationError::WorkLimitExceeded);
            }
            normalization_state.stats.permutations += 1;
            let mut issuer_copy = issuer.clone();
            let mut path = String::new();
            let mut recursion_list = Vec::new();
            for &related in &blank_node_list {
                if let Some(canonical_identifier) = normalization_state
                    .canonical_issuer
                    .find_issued_identifier(related)
                {
                    path.push_str(canonical_identifier.as_str());
                } else {
                    if issuer_copy.find_issued_identifier(related).is_none() {
                        recursion_list.push(related);
                    }
                    path.push_str(&issue_identifier(&mut issuer_copy, related));
                }
                if !chosen_path.is_empty() && path.len() >= chosen_path.len() && path > chosen_path
                {
                    continue 'permutations;
                }
            }
            for related in recursion_list {
                // Check before descending, also avoiding overflow when forming the next depth.
                if depth >= normalization_state.limits.max_recursion_depth {
                    return Err(NormalizationError::RecursionLimitExceeded);
                }
                path.push_str(&issue_identifier(&mut issuer_copy, related));
                let result =
                    hash_n_degree_quads(normalization_state, related, issuer_copy, depth + 1)?;
                path.push('<');
                path.push_str(&result.hash);
                path.push('>');
                issuer_copy = result.issuer;
                if !chosen_path.is_empty() && path.len() >= chosen_path.len() && path > chosen_path
                {
                    continue 'permutations;
                }
            }
            if chosen_issuer.is_none() || path < chosen_path {
                chosen_path = path;
                chosen_issuer = Some(issuer_copy);
            }
        }
        data_to_hash.push_str(&chosen_path);
        issuer = chosen_issuer.ok_or(NormalizationError::MissingChosenIssuer)?;
    }
    let hash = digest_to_lowerhex(&sha256(data_to_hash.as_bytes()));
    Ok(HashNDegreeQuadsOutput { hash, issuer })
}

/// <https://www.w3.org/TR/rdf-canon/#hash-related-blank-node>
fn hash_related_blank_node(
    normalization_state: &NormalizationState,
    related: &BlankId,
    quad: QuadRef,
    issuer: &IdentifierIssuer,
    position: BlankIdPosition,
) -> String {
    let identifier = normalization_state
        .canonical_issuer
        .find_issued_identifier(related)
        .or_else(|| issuer.find_issued_identifier(related))
        .map(BlankId::as_str)
        .unwrap_or_else(|| normalization_state.first_degree_hashes[related].as_str());
    let mut input = position.to_string();
    if position != BlankIdPosition::Graph {
        input.push('<');
        input.push_str(quad.predicate().as_str());
        input.push('>');
    }
    input.push_str(identifier);
    digest_to_lowerhex(&sha256(input.as_bytes()))
}

#[cfg(test)]
mod tests {
    use locspan::Meta;
    use nquads_syntax::Parse;

    use super::*;

    #[test]
    /// <https://json-ld.github.io/rdf-dataset-canonicalization/tests/>
    fn normalization_test_suite() {
        use std::fs::{self};
        use std::path::PathBuf;
        let case = std::env::args().nth(2);
        // Example usage to run a single test case:
        //   cargo test normalization_test_suite -- test022
        let mut passed = 0;
        let mut total = 0;
        for entry in fs::read_dir("../json-ld-normalization/tests").unwrap() {
            let entry = entry.unwrap();
            let filename = entry.file_name().into_string().unwrap();
            if !filename.starts_with("test") || !filename.ends_with("-urdna2015.nq") {
                continue;
            }
            let num = &filename[0..7].to_string();
            if let Some(ref case) = case {
                if case != num {
                    continue;
                }
            }
            total += 1;
            let mut path = entry.path();
            let expected_str = fs::read_to_string(&path).unwrap();
            let in_file_name = num.to_string() + "-in.nq";
            path.set_file_name(PathBuf::from(in_file_name));
            let in_str = fs::read_to_string(&path).unwrap();
            let dataset = nquads_syntax::Document::parse_str(&in_str, |span| span).unwrap();
            let stripped_dataset: Vec<_> = dataset
                .into_value()
                .into_iter()
                .map(Meta::into_value)
                .map(Quad::strip_all_but_predicate)
                .collect();
            let normalized = normalize(stripped_dataset.iter().map(Quad::as_quad_ref))
                .unwrap()
                .into_nquads();
            if &normalized == &expected_str {
                passed += 1;
            } else {
                let changes = difference::Changeset::new(&normalized, &expected_str, "\n");
                eprintln!("test {}: failed. diff:\n{}", num, changes);
            }
        }
        assert!(total > 0);
        assert_eq!(passed, total);
    }
}
