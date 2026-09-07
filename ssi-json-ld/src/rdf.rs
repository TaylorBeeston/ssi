use std::{borrow::Borrow, fmt};

use iref::IriBuf;
use rdf_types::{Literal, Object, Quad, Subject};

/// RDF DataSet produced form a JSON-LD document.
pub type DataSet =
    grdf::HashDataset<rdf_types::Subject, IriBuf, rdf_types::Object, rdf_types::GraphLabel>;

/// N-Quads serialization used for both normalization hashes and output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NQuadsMode {
    /// Preserve the historical serializer and existing signature bases.
    Legacy,
    /// Canonical N-Quads as specified by RDF Dataset Canonicalization 1.0.
    Rdfc10,
}

/// Quad iterator extension to produce an N-Quads document.
///
/// See <https://www.w3.org/TR/n-quads/>.
pub trait IntoNQuads {
    fn into_nquads(self) -> String;

    fn into_nquads_with_mode(self, mode: NQuadsMode) -> String;
}

impl<Q: IntoIterator> IntoNQuads for Q
where
    Q::Item: Borrow<Quad>,
{
    fn into_nquads(self) -> String {
        self.into_nquads_with_mode(NQuadsMode::Legacy)
    }

    fn into_nquads_with_mode(self, mode: NQuadsMode) -> String {
        let mut lines = self
            .into_iter()
            .map(|quad| NQuadsStatementWithMode(quad.borrow(), mode).to_string())
            .collect::<Vec<String>>();
        lines.sort();
        lines.dedup();
        lines.join("")
    }
}

/// Wrapper to display an RDF Quad as an N-Quads statement.
pub struct NQuadsStatement<'a>(pub &'a Quad);

impl<'a> fmt::Display for NQuadsStatement<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} .", self.0)
    }
}

pub(crate) struct NQuadsStatementWithMode<'a>(pub &'a Quad, pub NQuadsMode);

impl fmt::Display for NQuadsStatementWithMode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.1 == NQuadsMode::Legacy {
            return NQuadsStatement(self.0).fmt(f);
        }

        fmt_rdfc_subject(&self.0 .0, f)?;
        f.write_str(" ")?;
        fmt_rdfc_iri(&self.0 .1, f)?;
        f.write_str(" ")?;
        match &self.0 .2 {
            Object::Blank(id) => write!(f, "{id}")?,
            Object::Iri(iri) => fmt_rdfc_iri(iri, f)?,
            Object::Literal(literal) => {
                f.write_str("\"")?;
                for c in literal.string_literal().as_ref().chars() {
                    match c {
                        '\u{08}' => f.write_str("\\b"),
                        '\t' => f.write_str("\\t"),
                        '\n' => f.write_str("\\n"),
                        '\u{0c}' => f.write_str("\\f"),
                        '\r' => f.write_str("\\r"),
                        '"' => f.write_str("\\\""),
                        '\\' => f.write_str("\\\\"),
                        '\u{00}'..='\u{07}'
                        | '\u{0b}'
                        | '\u{0e}'..='\u{1f}'
                        | '\u{7f}'
                        | '\u{fffe}'
                        | '\u{ffff}' => write!(f, "\\u{:04X}", c as u32),
                        _ => write!(f, "{c}"),
                    }?;
                }
                f.write_str("\"")?;
                match literal {
                    Literal::TypedString(_, datatype)
                        if datatype.as_str() != "http://www.w3.org/2001/XMLSchema#string" =>
                    {
                        f.write_str("^^")?;
                        fmt_rdfc_iri(datatype, f)?;
                    }
                    Literal::LangString(_, language) => write!(f, "@{language}")?,
                    _ => {}
                }
            }
        }
        if let Some(graph) = &self.0 .3 {
            f.write_str(" ")?;
            fmt_rdfc_subject(graph, f)?;
        }
        f.write_str(" .\n")
    }
}

fn fmt_rdfc_subject(subject: &Subject, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match subject {
        Subject::Blank(id) => write!(f, "{id}"),
        Subject::Iri(iri) => fmt_rdfc_iri(iri, f),
    }
}

fn fmt_rdfc_iri(iri: &IriBuf, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    // Valid RDF IRIs are emitted unchanged, including native Unicode.
    write!(f, "<{iri}>")
}
