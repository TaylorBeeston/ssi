use locspan::Meta;
use nquads_syntax::Parse;
use rdf_types::{BlankIdBuf, Quad};
use ssi_json_ld::urdna2015::{
    normalize, normalize_with_limits, BlankNodeComponentsMut, NormalizationError,
    NormalizationLimits,
};

// Ordinary W3C vectors: a directed three-node cycle and a blank-node-named graph.
const CYCLE: &str = include_str!("../../json-ld-normalization/tests/test023-in.nq");
const CANONICAL_CYCLE: &str =
    include_str!("../../json-ld-normalization/tests/test023-urdna2015.nq");
const NAMED_GRAPH: &str = include_str!("../../json-ld-normalization/tests/test058-in.nq");
const CANONICAL_NAMED_GRAPH: &str =
    include_str!("../../json-ld-normalization/tests/test058-urdna2015.nq");

fn parse_quads(input: &str) -> Vec<Quad> {
    nquads_syntax::Document::parse_str(input, |span| span)
        .unwrap()
        .into_value()
        .into_iter()
        .map(Meta::into_value)
        .map(Quad::strip_all_but_predicate)
        .collect()
}

#[test]
fn named_graph_canonicalization_ignores_blank_labels_and_quad_order() {
    for rename in [false, true] {
        for reverse in [false, true] {
            let mut quads = parse_quads(NAMED_GRAPH);
            if rename {
                for quad in &mut quads {
                    for id in quad.blank_node_components_mut() {
                        // Change lexical ordering as well as graph and object labels.
                        let renamed = match id.as_str() {
                            "_:b0" => "_:z",
                            "_:b1" => "_:a",
                            "_:b3" => "_:graph",
                            _ => panic!("unexpected blank label in W3C test058"),
                        };
                        *id = BlankIdBuf::new(renamed.to_owned()).unwrap();
                    }
                }
            }
            if reverse {
                quads.reverse();
            }

            let normalized = normalize(quads.iter().map(Quad::as_quad_ref)).unwrap();
            assert_eq!(
                normalized.into_nquads(),
                CANONICAL_NAMED_GRAPH,
                "rename={rename}, reverse={reverse}"
            );
        }
    }
}

#[test]
fn small_cycle_matches_reference_with_default_limits() {
    let quads = parse_quads(CYCLE);
    let normalized = normalize_with_limits(
        quads.iter().map(Quad::as_quad_ref),
        NormalizationLimits::default(),
    )
    .unwrap();
    assert_eq!(normalized.into_nquads(), CANONICAL_CYCLE);
}

#[test]
fn small_cycle_returns_work_limit_error_instead_of_partial_output() {
    let quads = parse_quads(CYCLE);
    let result = normalize_with_limits(
        quads.iter().map(Quad::as_quad_ref),
        NormalizationLimits {
            max_permutations: 0,
            ..NormalizationLimits::default()
        },
    );
    assert!(matches!(result, Err(NormalizationError::WorkLimitExceeded)));
}

#[test]
fn small_cycle_returns_recursion_limit_error_instead_of_partial_output() {
    let quads = parse_quads(CYCLE);
    let result = normalize_with_limits(
        quads.iter().map(Quad::as_quad_ref),
        NormalizationLimits {
            max_recursion_depth: 1,
            ..NormalizationLimits::default()
        },
    );
    assert!(matches!(
        result,
        Err(NormalizationError::RecursionLimitExceeded)
    ));
}
