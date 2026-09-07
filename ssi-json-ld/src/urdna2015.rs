use std::collections::BTreeMap as Map;
use std::collections::HashSet;
use std::fmt;

#[derive(Debug)]
pub struct MissingChosenIssuer;

use rdf_types::BlankId;
use rdf_types::QuadRef;
use rdf_types::{BlankIdBuf, Quad};

use ssi_crypto::hashes::sha256::sha256;

use crate::rdf::{IntoNQuads, NQuadsMode, NQuadsStatementWithMode};

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
pub struct NormalizationState<'a> {
    pub blank_node_to_quads: Map<&'a BlankId, Vec<QuadRef<'a>>>,
    pub hash_to_blank_nodes: Map<String, Vec<&'a BlankId>>,
    pub canonical_issuer: IdentifierIssuer,
    pub nquads_mode: NQuadsMode,
}

/// <https://www.w3.org/TR/rdf-canon/#dfn-identifier-issuer>  
/// <https://www.w3.org/TR/rdf-canon/#blank-node-identifier-issuer-state>
#[derive(Debug, Clone)]
pub struct IdentifierIssuer {
    pub identifier_prefix: String,
    pub identifier_counter: u64,
    pub issued_identifiers_list: Vec<(BlankIdBuf, BlankIdBuf)>,
}

impl IdentifierIssuer {
    pub fn new(prefix: String) -> Self {
        Self {
            identifier_prefix: prefix,
            identifier_counter: 0,
            issued_identifiers_list: Vec::new(),
        }
    }
    pub fn find_issued_identifier(&self, existing_identifier: &BlankId) -> Option<&BlankId> {
        // TODO(optimize): index issued_identifiers_list by existing_identifier
        self.issued_identifiers_list
            .iter()
            .find(|(_, existing_id)| existing_id == existing_identifier)
            .map(|(issued_identifier, _)| issued_identifier.as_ref())
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
pub fn hash_first_degree_quads(
    normalization_state: &mut NormalizationState,
    reference_blank_node_identifier: &BlankId,
) -> String {
    // https://www.w3.org/TR/rdf-canon/#algorithm-1
    // 1
    let mut nquads: Vec<String> = Vec::new();
    // 2
    if let Some(quads) = normalization_state
        .blank_node_to_quads
        .get(reference_blank_node_identifier)
    {
        // 3
        for quad in quads {
            // 3.1
            let mut quad: Quad = quad.into_owned();
            // 3.1.1
            for label in quad.blank_node_components_mut() {
                // 3.1.1.1
                *label = if label == reference_blank_node_identifier {
                    BlankIdBuf::from_suffix("a").unwrap()
                } else {
                    BlankIdBuf::from_suffix("z").unwrap()
                };
            }
            let nquad = NQuadsStatementWithMode(&quad, normalization_state.nquads_mode).to_string();
            nquads.push(nquad);
        }
    }
    // 4
    nquads.sort();
    // 5
    let joined_nquads = nquads.join("");
    let nquads_digest = sha256(joined_nquads.as_bytes());
    digest_to_lowerhex(&nquads_digest)
}

/// <https://www.w3.org/TR/rdf-canon/>
pub fn normalize<'a, Q: IntoIterator<Item = QuadRef<'a>>>(
    quads: Q,
) -> NormalizedQuads<'a, Q::IntoIter>
where
    Q::IntoIter: Clone,
{
    normalize_with_mode(quads, NQuadsMode::Legacy)
}

/// Normalize using one serialization mode for first-degree hashes and output.
pub fn normalize_with_mode<'a, Q: IntoIterator<Item = QuadRef<'a>>>(
    quads: Q,
    mode: NQuadsMode,
) -> NormalizedQuads<'a, Q::IntoIter>
where
    Q::IntoIter: Clone,
{
    // https://www.w3.org/TR/rdf-canon/#algorithm
    // 1
    let mut normalization_state = NormalizationState {
        blank_node_to_quads: Map::new(),
        hash_to_blank_nodes: Map::new(),
        canonical_issuer: IdentifierIssuer::new("_:c14n".to_string()),
        nquads_mode: mode,
    };
    // 2
    let quads = quads.into_iter();
    for quad in quads.clone() {
        // 2.1
        for blank_node_identifier in quad.blank_node_components() {
            normalization_state
                .blank_node_to_quads
                .entry(blank_node_identifier)
                .or_default()
                .push(quad);
        }
    }
    // 3
    let mut non_normalized_identifiers: HashSet<&BlankId> = normalization_state
        .blank_node_to_quads
        .keys()
        .cloned()
        .collect();
    // 4
    let mut simple = true;
    // 5
    while simple {
        // 5.1
        simple = false;
        // 5.2
        normalization_state.hash_to_blank_nodes.clear();
        // 5.3
        for identifier in non_normalized_identifiers.iter() {
            // 5.3.1
            let hash = hash_first_degree_quads(&mut normalization_state, identifier);
            // 5.3.2
            normalization_state
                .hash_to_blank_nodes
                .entry(hash)
                .or_default()
                .push(identifier);
        }
        // 5.4
        let mut hashes_to_remove = Vec::new();
        for (hash, identifier_list) in normalization_state.hash_to_blank_nodes.iter() {
            // 5.4.1
            if identifier_list.len() > 1 {
                continue;
            }
            // 5.4.2
            let identifier = match identifier_list.iter().next() {
                Some(id) => id,
                None => continue,
            };
            // note: canonical issuer is not passed
            issue_identifier(&mut normalization_state.canonical_issuer, identifier);
            // 5.4.3
            non_normalized_identifiers.remove(identifier);
            // 5.4.4
            // Cannot remove while iterating
            hashes_to_remove.push(hash.clone());
            // 5.4.5
            simple = true;
        }
        for hash in hashes_to_remove {
            normalization_state.hash_to_blank_nodes.remove(&hash);
        }
        // 6
        // Clone normalization_state to avoid mutable borrow
        for (_hash, identifier_list) in normalization_state.hash_to_blank_nodes.clone() {
            // 6.1
            let mut hash_path_list: Vec<HashNDegreeQuadsOutput> = Vec::new();
            // 6.2
            for identifier in identifier_list {
                // 6.2.1
                if normalization_state
                    .canonical_issuer
                    .find_issued_identifier(identifier)
                    .is_some()
                {
                    continue;
                }
                // 6.2.2
                let mut temporary_issuer = IdentifierIssuer::new("_:b".to_string());
                // 6.2.3
                issue_identifier(&mut temporary_issuer, identifier);
                // 6.2.4
                hash_path_list.push(
                    hash_n_degree_quads(
                        &mut normalization_state,
                        identifier,
                        &mut temporary_issuer,
                    )
                    .unwrap(),
                );
            }
            // 6.3
            hash_path_list.sort_by(|a, b| a.hash.cmp(&b.hash));
            for result in hash_path_list {
                // 6.3.1
                let identifier_issuer = result.issuer;
                for (_, existing_identifier) in identifier_issuer.issued_identifiers_list {
                    issue_identifier(
                        &mut normalization_state.canonical_issuer,
                        &existing_identifier,
                    );
                }
            }
        }
    }
    // 7
    NormalizedQuads {
        quads,
        normalization_state,
    }
}

pub struct NormalizedQuads<'a, Q> {
    quads: Q,
    normalization_state: NormalizationState<'a>,
}

impl<'a, Q: Iterator<Item = QuadRef<'a>>> NormalizedQuads<'a, Q> {
    pub fn into_nquads(self) -> String {
        let mode = self.normalization_state.nquads_mode;
        IntoNQuads::into_nquads_with_mode(self, mode)
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
    identifier_issuer
        .issued_identifiers_list
        .push((issued_identifier.clone(), existing_identifier.to_owned()));
    // 4
    identifier_issuer.identifier_counter += 1;
    // 5
    issued_identifier
}

/// <https://www.w3.org/TR/rdf-canon/#hash-n-degree-quads>
pub fn hash_n_degree_quads(
    normalization_state: &mut NormalizationState,
    identifier: &BlankId,
    issuer: &mut IdentifierIssuer,
) -> Result<HashNDegreeQuadsOutput, MissingChosenIssuer> {
    let mut issuer = issuer;
    // https://www.w3.org/TR/rdf-canon/#algorithm-3
    let mut issuer_tmp: IdentifierIssuer;
    // 1
    let mut hash_to_related_blank_nodes: Map<String, Vec<&BlankId>> = Map::new();
    // 2
    if let Some(quads) = normalization_state
        .blank_node_to_quads
        .get(identifier)
        // Clone to prevent multiple mutable borrows of normalization state
        .cloned()
    {
        // 3
        for quad in quads {
            // 3.1
            for (component, position) in quad.blank_node_components_with_position() {
                // Not checking for predicate since that cannot be a blank node identifier anyway
                if component != identifier {
                    // 3.1.1
                    let hash = hash_related_blank_node(
                        normalization_state,
                        component,
                        quad,
                        issuer,
                        position,
                    );
                    // 3.1.2
                    hash_to_related_blank_nodes
                        .entry(hash)
                        .or_default()
                        .push(component);
                }
            }
        }
    }
    // 4
    let mut data_to_hash = String::new();
    // 5
    // Using BTreeMap for sort by hash
    for (related_hash, blank_node_list) in hash_to_related_blank_nodes {
        // 5.1
        data_to_hash.push_str(&related_hash);
        // 5.2
        let mut chosen_path = String::new();
        // 5.3
        let mut chosen_issuer = None;
        // 5.4
        for permutation in combination::permutate::from_vec(&blank_node_list) {
            // 5.4.1
            let mut issuer_copy = issuer.clone();
            // 5.4.2
            let mut path = String::new();
            // 5.4.3
            let mut recursion_list: Vec<BlankIdBuf> = Vec::new();
            // 5.4.4
            for related in permutation {
                // 5.4.4.1
                if let Some(canonical_identifier) = normalization_state
                    .canonical_issuer
                    .find_issued_identifier(related)
                    .as_ref()
                {
                    recursion_list.push((*canonical_identifier).to_owned());
                // 5.4.4.2
                } else {
                    // 5.4.4.2.1
                    if issuer_copy.find_issued_identifier(related).is_none() {
                        recursion_list.push(related.to_owned());
                    }
                    // 5.4.4.2.2
                    path += &issue_identifier(&mut issuer_copy, related);
                }
                // 5.4.4.3
                if !chosen_path.is_empty() && path.len() >= chosen_path.len() && path > chosen_path
                {
                    continue;
                }
            }
            // 5.4.5
            for related in recursion_list {
                // 5.4.5.1
                let result = hash_n_degree_quads(normalization_state, &related, &mut issuer_copy)?;
                // 5.4.5.2
                path.push_str(&issue_identifier(&mut issuer_copy, &related));
                // 5.4.5.3
                path.push('<');
                path.push_str(&result.hash);
                path.push('>');
                // 5.4.5.4
                issuer_copy = result.issuer;
                // 5.4.5.5
                if !chosen_path.is_empty() && path.len() >= chosen_path.len() && path > chosen_path
                {
                    continue;
                }
            }
            // 5.4.6
            if chosen_path.is_empty() || path < chosen_path {
                chosen_path = path;
                chosen_issuer.replace(issuer_copy);
            }
        }
        // 5.5
        data_to_hash.push_str(&chosen_path);
        // 5.6
        issuer_tmp = match chosen_issuer {
            Some(issuer) => issuer,
            None => return Err(MissingChosenIssuer),
        };
        issuer = &mut issuer_tmp;
    }
    // 6
    let digest = sha256(data_to_hash.as_bytes());
    let hash = digest_to_lowerhex(&digest);
    Ok(HashNDegreeQuadsOutput {
        hash,
        issuer: issuer.to_owned(),
    })
}

/// <https://www.w3.org/TR/rdf-canon/#hash-related-blank-node>
pub fn hash_related_blank_node(
    normalization_state: &mut NormalizationState,
    related: &BlankId,
    quad: QuadRef,
    issuer: &mut IdentifierIssuer,
    position: BlankIdPosition,
) -> String {
    // https://www.w3.org/TR/rdf-canon/#algorithm-2
    // 1
    let identifier = match normalization_state
        .canonical_issuer
        .find_issued_identifier(related)
    {
        Some(id) => id.to_string(),
        None => match issuer.find_issued_identifier(related) {
            Some(id) => id.to_string(),
            None => hash_first_degree_quads(normalization_state, related),
        },
    };
    // 2
    let mut input = position.to_string();
    // 3
    if position != BlankIdPosition::Graph {
        input.push('<');
        input.push_str(quad.predicate().as_str());
        input.push('>');
    }
    // 4
    input += &identifier;
    // 5
    let digest = sha256(input.as_bytes());
    digest_to_lowerhex(&digest)
}

#[cfg(test)]
mod tests {
    use locspan::Meta;
    use nquads_syntax::Parse;

    use super::*;

    fn literal_quad(id: &str, value: &str) -> Quad {
        Quad(
            rdf_types::Subject::Blank(BlankIdBuf::from_suffix(id).unwrap()),
            iref::IriBuf::new("urn:p").unwrap(),
            rdf_types::Object::Literal(rdf_types::Literal::String(value.to_string().into())),
            None,
        )
    }

    #[test]
    fn rdfc_normalization_hashes_canonical_literal_escapes() {
        let quads = [
            literal_quad("control", "\u{1f}"),
            literal_quad("text", "plain"),
        ];
        // SHA-256 of the first-degree lines with _:a:
        // escaped control: 4dfd27725af85be65e0177b549d1caf4dfeec44ca602bdf49e312a147033f3dc
        // plain:           b86ab59dbbb25e47563d26343cf110fa3a720281828f47f5fb8dc088df4c23f5
        // raw control:     fc3e9adff6e220c3b4d5873a792a337f33ec930ef0ed1cac0df6116e536930b3
        // Thus escaping only final output would give the wrong canonical labels.
        let normalized =
            normalize_with_mode(quads.iter().map(Quad::as_quad_ref), NQuadsMode::Rdfc10)
                .into_nquads();
        assert_eq!(
            normalized,
            concat!(
                "_:c14n0 <urn:p> \"\\u001F\" .\n",
                "_:c14n1 <urn:p> \"plain\" .\n"
            )
        );
    }

    #[test]
    fn legacy_normalization_preserves_literal_bytes_and_labels() {
        let quads = [
            literal_quad("control", "\u{1f}"),
            literal_quad("text", "plain"),
        ];
        let expected = concat!(
            "_:c14n0 <urn:p> \"plain\" .\n",
            "_:c14n1 <urn:p> \"\u{1f}\" .\n"
        );
        assert_eq!(
            normalize(quads.iter().map(Quad::as_quad_ref)).into_nquads(),
            expected
        );
        assert_eq!(
            normalize_with_mode(quads.iter().map(Quad::as_quad_ref), NQuadsMode::Legacy)
                .into_nquads(),
            expected
        );
        assert_eq!(
            crate::rdf::NQuadsStatement(&quads[0]).to_string(),
            "_:control <urn:p> \"\u{1f}\" .\n"
        );
    }

    #[test]
    fn rdfc_canonical_nquads_literal_escaping() {
        // https://www.w3.org/TR/rdf-canon/#canonical-quads
        // All C0 characters, DEL, XML 1.1 exclusions, ECHAR punctuation, and
        // representative native Unicode (including non-BMP characters).
        let value = concat!(
            "\u{00}\u{01}\u{02}\u{03}\u{04}\u{05}\u{06}\u{07}",
            "\u{08}\t\n\u{0b}\u{0c}\r\u{0e}\u{0f}",
            "\u{10}\u{11}\u{12}\u{13}\u{14}\u{15}\u{16}\u{17}",
            "\u{18}\u{19}\u{1a}\u{1b}\u{1c}\u{1d}\u{1e}\u{1f}",
            "\u{7f}\u{fffe}\u{ffff}\"\\/\u{85}\u{2028}é\u{1f642}\u{10ffff}"
        );
        let quad = literal_quad("literal", value);
        assert_eq!(
            [&quad].into_nquads_with_mode(NQuadsMode::Rdfc10),
            concat!(
                "_:literal <urn:p> \"",
                "\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007",
                "\\b\\t\\n\\u000B\\f\\r\\u000E\\u000F",
                "\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017",
                "\\u0018\\u0019\\u001A\\u001B\\u001C\\u001D\\u001E\\u001F",
                "\\u007F\\uFFFE\\uFFFF\\\"\\\\/\u{85}\u{2028}é\u{1f642}\u{10ffff}",
                "\" .\n"
            )
        );
    }

    #[test]
    fn rdfc_canonical_nquads_preserves_rdf_terms() {
        let input = concat!(
            "<urn:é> <urn:p> <urn:o> <urn:g> .\n",
            "_:s <urn:p> _:o _:g .\n",
            "_:s <urn:p> \"bonjour\\t\"@fr .\n",
            "_:s <urn:p> \"42\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n"
        );
        let dataset = nquads_syntax::Document::parse_str(input, |span| span).unwrap();
        let mut quads: Vec<_> = dataset
            .into_value()
            .into_iter()
            .map(Meta::into_value)
            .map(Quad::strip_all_but_predicate)
            .collect();
        quads.push(Quad(
            rdf_types::Subject::Blank(BlankIdBuf::from_suffix("s").unwrap()),
            iref::IriBuf::new("urn:p").unwrap(),
            rdf_types::Object::Literal(rdf_types::Literal::TypedString(
                "string".to_string().into(),
                iref::IriBuf::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
            )),
            None,
        ));
        assert_eq!(
            quads.into_nquads_with_mode(NQuadsMode::Rdfc10),
            concat!(
                "<urn:é> <urn:p> <urn:o> <urn:g> .\n",
                "_:s <urn:p> \"42\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
                "_:s <urn:p> \"bonjour\\t\"@fr .\n",
                "_:s <urn:p> \"string\" .\n",
                "_:s <urn:p> _:o _:g .\n"
            )
        );
    }

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
            let normalized =
                normalize(stripped_dataset.iter().map(Quad::as_quad_ref)).into_nquads();
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
