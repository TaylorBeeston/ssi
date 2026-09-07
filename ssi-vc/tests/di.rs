use std::collections::HashMap;

use async_trait::async_trait;
use did_method_key::DIDKey;
use rstest::*;
use serde::Deserialize;
use ssi_dids::{
    did_resolve::{
        Content, ContentMetadata, DIDResolver, DereferencingInputMetadata, DereferencingMetadata,
        DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, TYPE_DID_LD_JSON,
    },
    Document, PrimaryDIDURL,
};
use ssi_json_ld::{rdf::NQuadsMode, urdna2015, ContextLoader};
use ssi_jwk::{Algorithm, JWK};
use ssi_ldp::{
    dataintegrity::DataIntegrityCryptoSuite, LinkedDataDocument, Proof, ProofSuite, ProofSuiteType,
    SigningInput,
};
use ssi_vc::{Credential, LinkedDataProofOptions, OneOrMany, ProofPurpose, URI};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPair {
    public_key_multibase: String,
    private_key_multibase: String,
}

struct DiResolver;

const DI_ISSUER: &str = "https://vc.example/issuers/5678";
const DI_ISSUER_JSON: &str = r#"{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "id": "https://vc.example/issuers/5678",
  "assertionMethod": [
    {
      "@context": "https://w3id.org/security/multikey/v1",
      "id": "https://vc.example/issuers/5678#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
      "controller": "https://vc.example/issuers/5678",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
    },
    {
      "@context": "https://w3id.org/security/multikey/v1",
      "id": "https://vc.example/issuers/5678#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
      "controller": "https://vc.example/issuers/5678",
      "type": "Multikey",
      "publicKeyMultibase": "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"
    },
    {
      "@context": "https://w3id.org/security/multikey/v1",
      "id": "https://vc.example/issuers/5678#z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ",
      "controller": "https://vc.example/issuers/5678",
      "type": "Multikey",
      "publicKeyMultibase": "z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ"
    }
  ]
}"#;

#[async_trait]
impl DIDResolver for DiResolver {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        if did.starts_with("did:key:") {
            return DIDKey.resolve(did, _input_metadata).await;
        }
        if did == DI_ISSUER {
            let doc = Document::from_json(DI_ISSUER_JSON).expect("Could not deserialize document");
            (
                ResolutionMetadata {
                    content_type: Some(TYPE_DID_LD_JSON.to_string()),
                    ..Default::default()
                },
                Some(doc),
                Some(DocumentMetadata::default()),
            )
        } else if did == "https:" {
            (
                ResolutionMetadata {
                    content_type: Some(TYPE_DID_LD_JSON.to_string()),
                    ..Default::default()
                },
                Some(Document::new(did)),
                Some(DocumentMetadata::default()),
            )
        } else {
            panic!("Invalid did for di-eddsa");
        }
    }

    async fn resolve_representation(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
        if did.starts_with("did:key:") {
            return DIDKey.resolve_representation(did, _input_metadata).await;
        }
        if did == DI_ISSUER {
            let vec = DI_ISSUER_JSON.as_bytes().to_vec();
            (
                ResolutionMetadata {
                    error: None,
                    content_type: Some(TYPE_DID_LD_JSON.to_string()),
                    property_set: None,
                },
                vec,
                Some(DocumentMetadata::default()),
            )
        } else {
            panic!("Invalid did for di-eddsa");
        }
    }

    async fn dereference(
        &self,
        did_url: &PrimaryDIDURL,
        _input_metadata: &DereferencingInputMetadata,
    ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
        if did_url.to_string().starts_with("did:key:") {
            return DIDKey.dereference(did_url, _input_metadata).await;
        }
        let doc = Document::from_json(DI_ISSUER_JSON).expect("Could not deserialize document");
        match &did_url.to_string()[..] {
            "https://vc.example/issuers/5678" => Some((
                DereferencingMetadata {
                    content_type: Some(TYPE_DID_LD_JSON.to_string()),
                    ..Default::default()
                },
                Content::DIDDocument(doc),
                ContentMetadata::default(),
            )),
            _ => None,
        }
    }
}

#[async_std::test]
async fn vc_di_eddsa_ed25519signature2020() {
    // let signed_vc = include_str!(
    //     "../../tests/vc-di-eddsa/TestVectors/Ed25519Signature2020/signedEdSig.json"
    // );
    // let mut signed_vc: Credential = serde_json::from_str(signed_vc).unwrap();
    // let proofs = signed_vc.proof.unwrap();
    // let mut proof = proofs.first().unwrap().clone();
    // proof.context = serde_json::Value::String(
    //     "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
    // );
    // signed_vc.proof = Some(OneOrMany::One(proof));
    // let res = signed_vc
    //     .verify(None, &DiEddsaResolver, &mut ContextLoader::default())
    //     .await;
    // assert_eq!(res.errors, Vec::<String>::default());

    let unsigned_vc = include_str!("../../tests/vc-di-eddsa/TestVectors/unsigned.json");
    let mut unsigned_vc: Credential = serde_json::from_str(unsigned_vc).unwrap();
    let key: KeyPair = serde_json::from_str(include_str!(
        "../../tests/vc-di-eddsa/TestVectors/keyPair.json"
    ))
    .unwrap();
    let jwk = JWK::from_multicodec(&key.private_key_multibase).unwrap();
    let proof = unsigned_vc
        .generate_proof(
            &jwk,
            &LinkedDataProofOptions {
                type_: Some(ProofSuiteType::Ed25519Signature2020),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                verification_method: Some(URI::String("https://vc.example/issuers/5678#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2".into())),
                ..Default::default()
            },
            &DiResolver,
            &mut ContextLoader::default(),
        )
        .await
        .unwrap();
    assert!(proof.proof_value.is_some());
    unsigned_vc.proof = Some(OneOrMany::One(proof));
    let res = unsigned_vc
        .verify(None, &DiResolver, &mut ContextLoader::default())
        .await;
    assert_eq!(res.errors, Vec::<String>::default());
}

struct TestParams {
    signed_vc: String,
    unsigned_vc: String,
    keypair: String,
    cryptosuite: Option<DataIntegrityCryptoSuite>,
}

#[fixture]
fn test_cases() -> HashMap<String, TestParams> {
    vec![
        (
            "eddsa2022".into(),
            TestParams {
                signed_vc: include_str!(
                    "../../tests/vc-di-eddsa/TestVectors/eddsa-2022/signedDataInt.json"
                )
                .into(),
                unsigned_vc: include_str!("../../tests/vc-di-eddsa/TestVectors/unsigned.json")
                    .into(),
                keypair: include_str!("../../tests/vc-di-eddsa/TestVectors/keyPair.json").into(),
                cryptosuite: Some(DataIntegrityCryptoSuite::Eddsa2022),
            },
        ),
        (
            "jcseddsa2022".into(),
            TestParams {
                signed_vc: include_str!(
                               "../../tests/vc-di-eddsa/TestVectors/jcs-eddsa-2022/signedJCS.json"
                               )
                    .into(),
                    unsigned_vc: include_str!("../../tests/vc-di-eddsa/TestVectors/unsigned.json")
                        .into(),
                        keypair: include_str!("../../tests/vc-di-eddsa/TestVectors/keyPair.json").into(),
                        cryptosuite: Some(DataIntegrityCryptoSuite::JcsEddsa2022),
            },
            ),
        (
            "ecdsa2019p256".into(),
            TestParams {
                signed_vc: include_str!(
                    "../../tests/vc-di-ecdsa/TestVectors/ecdsa-2019-p256/signedECDSAP256.json"
                )
                .into(),
                unsigned_vc: include_str!("../../tests/vc-di-ecdsa/TestVectors/unsigned.json")
                    .into(),
                keypair: include_str!("../../tests/vc-di-ecdsa/TestVectors/p256KeyPair.json")
                    .into(),
                cryptosuite: None,
            },
        ),
        (
            "jcsecdsa2019p256".into(),
            TestParams {
                signed_vc: include_str!(
                    "../../tests/vc-di-ecdsa/TestVectors/jcs-ecdsa-2019-p256/signedJCSECDSAP256.json"
                )
                .into(),
                unsigned_vc: include_str!("../../tests/vc-di-ecdsa/TestVectors/unsigned.json")
                    .into(),
                keypair: include_str!("../../tests/vc-di-ecdsa/TestVectors/p256KeyPair.json")
                    .into(),
                cryptosuite: Some(DataIntegrityCryptoSuite::JcsEcdsa2019),
            },
        ),
        (
            "ecdsa2019p384".into(),
            TestParams {
                signed_vc: include_str!(
                    "../../tests/vc-di-ecdsa/TestVectors/ecdsa-2019-p384/signedECDSAP384.json"
                )
                .into(),
                unsigned_vc: include_str!("../../tests/vc-di-ecdsa/TestVectors/unsigned.json")
                    .into(),
                keypair: include_str!("../../tests/vc-di-ecdsa/TestVectors/p384KeyPair.json")
                    .into(),
                cryptosuite: None,
            },
        ),
        (
            "jcsecdsa2019p384".into(),
            TestParams {
                signed_vc: include_str!(
                    "../../tests/vc-di-ecdsa/TestVectors/jcs-ecdsa-2019-p384/signedJCSECDSAP384.json"
                )
                .into(),
                unsigned_vc: include_str!("../../tests/vc-di-ecdsa/TestVectors/unsigned.json")
                    .into(),
                keypair: include_str!("../../tests/vc-di-ecdsa/TestVectors/p384KeyPair.json")
                    .into(),
                cryptosuite: Some(DataIntegrityCryptoSuite::JcsEcdsa2019),
            },
        ),
    ]
    .into_iter()
    .collect()
}

#[rstest]
#[case::eddsa2022("eddsa2022")]
#[case::jcs_eddsa2022("jcseddsa2022")]
#[case::ecdsa2019_p256("ecdsa2019p256")]
#[case::jcs_ecdsa2019_p256("jcsecdsa2019p256")]
// #[ignore = "p384 requires the canon document/proof to be hashed with sha384 but it's defaulting to sha256"]
#[case::ecdsa2019_p384("ecdsa2019p384")]
#[case::jcs_ecdsa2019_p384("jcsecdsa2019p384")]
#[async_std::test]
async fn vc_dataintegrity(#[case] name: String, test_cases: HashMap<String, TestParams>) {
    let test_case = test_cases.get(&name).unwrap();
    let signed_vc: Credential = serde_json::from_str(&test_case.signed_vc).unwrap();
    let res = signed_vc
        .verify(None, &DiResolver, &mut ContextLoader::default())
        .await;
    assert_eq!(res.errors, Vec::<String>::default());

    let proofs = signed_vc.proof.unwrap();
    let signed_proof = proofs.first().unwrap();

    let mut unsigned_vc: Credential = serde_json::from_str(&test_case.unsigned_vc).unwrap();
    let key: KeyPair = serde_json::from_str(&test_case.keypair).unwrap();
    let jwk = JWK::from_multicodec(&key.private_key_multibase).unwrap();
    let proof = unsigned_vc
        .generate_proof(
            &jwk,
            &LinkedDataProofOptions {
                type_: Some(ProofSuiteType::DataIntegrityProof),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                verification_method: Some(URI::String(format!(
                    "https://vc.example/issuers/5678#{}",
                    key.public_key_multibase
                ))),
                cryptosuite: test_case.cryptosuite.clone(),
                ..Default::default()
            },
            &DiResolver,
            &mut ContextLoader::default(),
        )
        .await
        .unwrap();
    assert!(proof.proof_value.is_some());
    assert_eq!(proof.cryptosuite, signed_proof.cryptosuite);
    unsigned_vc.proof = Some(OneOrMany::One(proof));
    let res = unsigned_vc
        .verify(None, &DiResolver, &mut ContextLoader::default())
        .await;
    assert_eq!(res.errors, Vec::<String>::default());
}

// Final-spec vectors are deliberately separate from the unchanged draft submodules.
// Upstream revision and byte hashes: tests/vc-di-ecdsa-final/provenance.json.
const FINAL_UNSIGNED: &str =
    include_str!("../../tests/vc-di-ecdsa-final/TestVectors/unsigned.json");
const FINAL_SIGNED: &str = include_str!(
    "../../tests/vc-di-ecdsa-final/TestVectors/ecdsa-rdfc-2019-p256/signedECDSAP256.json"
);
const FINAL_PROOF_CONFIG: &str = include_str!(
    "../../tests/vc-di-ecdsa-final/TestVectors/ecdsa-rdfc-2019-p256/proofConfigECDSAP256.json"
);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FinalKeyPair {
    public_key_multibase: String,
    secret_key_multibase: String,
}

fn final_keypair() -> FinalKeyPair {
    serde_json::from_str(include_str!(
        "../../tests/vc-di-ecdsa-final/TestVectors/p256KeyPair.json"
    ))
    .unwrap()
}

fn final_options() -> LinkedDataProofOptions {
    let proof: Proof = serde_json::from_str(FINAL_PROOF_CONFIG).unwrap();
    LinkedDataProofOptions {
        type_: Some(ProofSuiteType::DataIntegrityProof),
        cryptosuite: Some(DataIntegrityCryptoSuite::EcdsaRdfc2019),
        verification_method: proof.verification_method.map(URI::String),
        proof_purpose: proof.proof_purpose,
        created: proof.created,
        ..Default::default()
    }
}

#[async_std::test]
async fn vc_di_ecdsa_rdfc_2019_external_signature() {
    let signed: Credential = serde_json::from_str(FINAL_SIGNED).unwrap();
    let result = signed
        .verify(None, &DiResolver, &mut ContextLoader::default())
        .await;
    assert!(result.errors.is_empty(), "{:#?}", result);

    // The external signature is raw r || s in Base58btc, not DER or base64url.
    let proof = signed.proof.as_ref().unwrap().first().unwrap();
    let (base, signature) = multibase::decode(proof.proof_value.as_ref().unwrap()).unwrap();
    assert_eq!(base, multibase::Base::Base58Btc);
    assert_eq!(signature.len(), 64);
    assert_eq!(
        hex::encode(signature),
        include_str!(
            "../../tests/vc-di-ecdsa-final/TestVectors/ecdsa-rdfc-2019-p256/sigHexECDSAP256.txt"
        )
    );
}

#[async_std::test]
async fn vc_di_ecdsa_rdfc_2019_known_answer_sign_and_prepare() {
    let unsigned: Credential = serde_json::from_str(FINAL_UNSIGNED).unwrap();
    let config: Proof = serde_json::from_str(FINAL_PROOF_CONFIG).unwrap();
    let pair = final_keypair();
    let secret = JWK::from_multicodec(&pair.secret_key_multibase).unwrap();
    let public = JWK::from_multicodec(&pair.public_key_multibase).unwrap();
    let options = final_options();
    let mut loader = ContextLoader::default();

    let document_dataset = unsigned
        .to_dataset_for_signing(None, &mut loader)
        .await
        .unwrap();
    let document_canonical = urdna2015::normalize_with_mode(
        document_dataset.quads().map(Into::into),
        NQuadsMode::Rdfc10,
    )
    .into_nquads();
    assert_eq!(
        document_canonical,
        include_str!(
            "../../tests/vc-di-ecdsa-final/TestVectors/ecdsa-rdfc-2019-p256/canonDocECDSAP256.txt"
        )
    );
    let proof_dataset = config
        .to_dataset_for_signing(Some(&unsigned), &mut loader)
        .await
        .unwrap();
    let proof_canonical =
        urdna2015::normalize_with_mode(proof_dataset.quads().map(Into::into), NQuadsMode::Rdfc10)
            .into_nquads();
    assert_eq!(
        proof_canonical,
        include_str!(
            "../../tests/vc-di-ecdsa-final/TestVectors/ecdsa-rdfc-2019-p256/proofCanonECDSAP256.txt"
        )
    );

    let prepared = unsigned
        .prepare_proof(&public, &options, &DiResolver, &mut loader)
        .await
        .unwrap();
    let message = match &prepared.signing_input {
        SigningInput::Bytes(bytes) => &bytes.0,
        _ => panic!("ECDSA RDFC must prepare byte signing input"),
    };
    assert_eq!(
        hex::encode(message),
        include_str!(
            "../../tests/vc-di-ecdsa-final/TestVectors/ecdsa-rdfc-2019-p256/combinedHashECDSAP256.txt"
        )
    );
    assert_eq!(
        hex::encode(&message[..32]),
        include_str!(
            "../../tests/vc-di-ecdsa-final/TestVectors/ecdsa-rdfc-2019-p256/proofHashECDSAP256.txt"
        )
    );
    assert_eq!(
        hex::encode(&message[32..]),
        include_str!(
            "../../tests/vc-di-ecdsa-final/TestVectors/ecdsa-rdfc-2019-p256/docHashECDSAP256.txt"
        )
    );

    // Completing with the upstream signature proves prepare interoperates independently
    // of this implementation's signing path.
    let completed = ProofSuiteType::DataIntegrityProof
        .complete(
            &prepared,
            include_str!(
                "../../tests/vc-di-ecdsa-final/TestVectors/ecdsa-rdfc-2019-p256/sigBTC58ECDSAP256.txt"
            ),
        )
        .await
        .unwrap();
    let mut completed_vc = unsigned.clone();
    completed_vc.proof = Some(OneOrMany::One(completed));
    let result = completed_vc.verify(None, &DiResolver, &mut loader).await;
    assert!(result.errors.is_empty(), "{:#?}", result);

    let generated = unsigned
        .generate_proof(&secret, &options, &DiResolver, &mut loader)
        .await
        .unwrap();
    let (base, signature) = multibase::decode(generated.proof_value.as_ref().unwrap()).unwrap();
    assert_eq!(base, multibase::Base::Base58Btc);
    assert_eq!(signature.len(), 64);
    // Verify against the external known-answer message, never compare randomized signatures.
    ssi_jws::verify_bytes(Algorithm::ES256, message, &public, &signature).unwrap();
    let mut generated_vc = unsigned;
    generated_vc.proof = Some(OneOrMany::One(generated));
    let result = generated_vc.verify(None, &DiResolver, &mut loader).await;
    assert!(result.errors.is_empty(), "{:#?}", result);
}

#[async_std::test]
async fn vc_di_ecdsa_rdfc_2019_without_created() {
    // The pinned upstream vector has created; this deliberately separate roundtrip
    // exercises the final suite's optional timestamp, including default proof selection.
    let mut credential: Credential = serde_json::from_str(FINAL_UNSIGNED).unwrap();
    let secret = JWK::from_multicodec(&final_keypair().secret_key_multibase).unwrap();
    let mut options = final_options();
    options.created = None;
    let mut loader = ContextLoader::default();
    let proof = credential
        .generate_proof(&secret, &options, &DiResolver, &mut loader)
        .await
        .unwrap();
    assert!(proof.created.is_none());
    credential.proof = Some(OneOrMany::One(proof));
    let result = credential.verify(None, &DiResolver, &mut loader).await;
    assert!(result.errors.is_empty(), "{:#?}", result);
    // A cutoff constrains timestamps that exist; it does not make created required.
    let result = credential
        .verify(
            Some(LinkedDataProofOptions {
                created: Some("2020-01-01T00:00:00Z".parse().unwrap()),
                ..Default::default()
            }),
            &DiResolver,
            &mut loader,
        )
        .await;
    assert!(result.errors.is_empty(), "{:#?}", result);
}

#[rstest]
#[case::document(false)]
#[case::signature(true)]
#[async_std::test]
async fn vc_di_ecdsa_rdfc_2019_rejects_tampering(#[case] alter_signature: bool) {
    let mut value: serde_json::Value = serde_json::from_str(FINAL_SIGNED).unwrap();
    if alter_signature {
        let (base, mut signature) =
            multibase::decode(value["proof"]["proofValue"].as_str().unwrap()).unwrap();
        signature[0] ^= 1;
        value["proof"]["proofValue"] = multibase::encode(base, signature).into();
    } else {
        value["credentialSubject"]["alumniOf"] = "A different school".into();
    }
    let credential: Credential = serde_json::from_value(value).unwrap();
    let result = credential
        .verify(None, &DiResolver, &mut ContextLoader::default())
        .await;
    assert!(!result.errors.is_empty(), "Tampered credential verified");
}
