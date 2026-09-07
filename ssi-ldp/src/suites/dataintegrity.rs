use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_dids::did_resolve::{resolve_key, resolve_vm, DIDResolver};
use ssi_json_ld::{
    ContextLoader, CREDENTIALS_V2_CONTEXT, W3ID_DATA_INTEGRITY_V1_CONTEXT,
    W3ID_DATA_INTEGRITY_V2_CONTEXT,
};
use ssi_jwk::{Algorithm, Base64urlUInt, JWK};
use ssi_jws::VerificationWarnings;

use std::{collections::HashMap as Map, fmt};

use crate::{
    document_has_context, jcs_normalize, sha256_normalized, sha384_normalized, to_jws_payload,
    to_rdfc_jws_payload, urdna2015_normalize, Error, LinkedDataDocument, LinkedDataProofOptions,
    Proof, ProofPreparation, ProofSuiteType, SigningInput,
};

pub struct DataIntegrityProof;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum DataIntegrityCryptoSuite {
    #[serde(rename = "eddsa-rdfc-2022")]
    EddsaRdfc2022,
    #[serde(rename = "eddsa-2022")]
    Eddsa2022,
    #[serde(rename = "json-eddsa-2022")]
    JcsEddsa2022,
    #[serde(rename = "ecdsa-2019")]
    Ecdsa2019,
    #[serde(rename = "ecdsa-rdfc-2019")]
    EcdsaRdfc2019,
    #[serde(rename = "jcs-ecdsa-2019")]
    JcsEcdsa2019,
}

impl DataIntegrityCryptoSuite {
    fn pick_from_jwk(jwk: &JWK) -> Result<Vec<Self>, Error> {
        match jwk.get_algorithm() {
            Some(Algorithm::EdDSA) => Ok(vec![
                Self::EddsaRdfc2022,
                Self::Eddsa2022,
                Self::JcsEddsa2022,
            ]),
            Some(Algorithm::ES256) => Ok(vec![
                Self::Ecdsa2019,
                Self::JcsEcdsa2019,
                Self::EcdsaRdfc2019,
            ]),
            Some(Algorithm::ES384) => Ok(vec![Self::Ecdsa2019, Self::JcsEcdsa2019]),
            Some(Algorithm::None) | None => Err(Error::MissingAlgorithm),
            Some(_) => Err(Error::UnsupportedCryptosuite),
        }
    }
}
impl TryFrom<&str> for DataIntegrityCryptoSuite {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "eddsa-rdfc-2022" => Ok(Self::EddsaRdfc2022),
            "eddsa-2022" => Ok(Self::Eddsa2022),
            "json-eddsa-2022" => Ok(Self::JcsEddsa2022),
            "ecdsa-2019" => Ok(Self::Ecdsa2019),
            "ecdsa-rdfc-2019" => Ok(Self::EcdsaRdfc2019),
            "jcs-ecdsa-2019" => Ok(Self::JcsEcdsa2019),
            _ => Err(Error::UnsupportedCryptosuite),
        }
    }
}

impl TryFrom<String> for DataIntegrityCryptoSuite {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

impl From<DataIntegrityCryptoSuite> for String {
    fn from(value: DataIntegrityCryptoSuite) -> Self {
        match value {
            DataIntegrityCryptoSuite::EddsaRdfc2022 => "eddsa-rdfc-2022".into(),
            DataIntegrityCryptoSuite::Eddsa2022 => "eddsa-2022".into(),
            DataIntegrityCryptoSuite::JcsEddsa2022 => "json-eddsa-2022".into(),
            DataIntegrityCryptoSuite::Ecdsa2019 => "ecdsa-2019".into(),
            DataIntegrityCryptoSuite::EcdsaRdfc2019 => "ecdsa-rdfc-2019".into(),
            DataIntegrityCryptoSuite::JcsEcdsa2019 => "jcs-ecdsa-2019".into(),
        }
    }
}

impl TryFrom<Value> for DataIntegrityCryptoSuite {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::String(s) => s.try_into(),
            _ => Err(Error::InvalidCryptosuiteType),
        }
    }
}

impl fmt::Display for DataIntegrityCryptoSuite {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", String::from(self.clone()))
    }
}

impl DataIntegrityProof {
    fn validate_final_key(key: &JWK) -> Result<(), Error> {
        let ssi_jwk::Params::EC(params) = &key.params else {
            return Err(Error::UnsupportedCurve);
        };
        if params.curve.as_deref() != Some("P-256") {
            return Err(Error::UnsupportedCurve);
        }
        if key.get_algorithm() != Some(Algorithm::ES256) {
            return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
        }
        #[cfg(feature = "secp256r1")]
        {
            p256::PublicKey::try_from(params)?;
            Ok(())
        }
        #[cfg(not(feature = "secp256r1"))]
        Err(Error::JWS(ssi_jws::Error::MissingFeatures("secp256r1")))
    }

    fn final_verification_key(vm: &ssi_dids::VerificationMethodMap) -> Result<JWK, Error> {
        if vm.type_ == "Multikey" {
            let encoded = vm
                .property_set
                .as_ref()
                .and_then(|properties| properties.get("publicKeyMultibase"))
                .and_then(Value::as_str)
                .ok_or(Error::MissingKey)?;
            let (base, bytes) = multibase::decode(encoded)?;
            if base != multibase::Base::Base58Btc {
                return Err(Error::ExpectedMultibaseZ);
            }
            // p256-pub (0x1200), encoded as its canonical unsigned varint.
            // Check the representation before get_jwk discards it.
            if !bytes.starts_with(&[0x80, 0x24]) {
                return Err(ssi_jwk::Error::MultibaseKeyPrefix.into());
            }
            if bytes.len() != 35 || !matches!(bytes[2], 0x02 | 0x03) {
                return Err(ssi_jwk::Error::InvalidKeyLength(bytes.len() - 2).into());
            }
        }
        let key = vm.get_jwk()?;
        Self::validate_final_key(&key)?;
        Ok(key)
    }

    async fn legacy_rdfc_jws_payload(
        cryptosuite: &DataIntegrityCryptoSuite,
        jwa: &Algorithm,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        context_loader: &mut ContextLoader,
    ) -> Result<Option<Vec<u8>>, Error> {
        if !matches!(
            cryptosuite,
            DataIntegrityCryptoSuite::Eddsa2022 | DataIntegrityCryptoSuite::Ecdsa2019
        ) {
            return Ok(None);
        }

        let (doc_normalized, sigopts_normalized) =
            urdna2015_normalize(document, proof, context_loader).await?;
        let sigopts_normalized =
            sigopts_normalized.replace("^^<https://w3id.org/security#cryptosuiteString>", "");
        let payload = match jwa {
            Algorithm::EdDSA | Algorithm::ES256 => {
                sha256_normalized(doc_normalized, sigopts_normalized)?
            }
            Algorithm::ES384 => sha384_normalized(doc_normalized, sigopts_normalized)?,
            _ => return Ok(None),
        };
        Ok(Some(payload))
    }

    async fn jws_payload(
        cryptosuite: &DataIntegrityCryptoSuite,
        jwa: &Algorithm,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        context_loader: &mut ContextLoader,
    ) -> Result<Vec<u8>, Error> {
        Ok(match (cryptosuite, jwa) {
            (DataIntegrityCryptoSuite::EddsaRdfc2022, Algorithm::EdDSA)
            | (DataIntegrityCryptoSuite::Eddsa2022, Algorithm::EdDSA)
            | (DataIntegrityCryptoSuite::Ecdsa2019, Algorithm::ES256) => {
                to_jws_payload(document, proof, context_loader).await?
            }
            (DataIntegrityCryptoSuite::EcdsaRdfc2019, Algorithm::ES256) => {
                to_rdfc_jws_payload(document, proof, context_loader).await?
            }
            (DataIntegrityCryptoSuite::JcsEddsa2022, Algorithm::EdDSA) => {
                let (doc_normalized, sigopts_normalized) = jcs_normalize(document, proof).await?;
                sha256_normalized(doc_normalized, sigopts_normalized)?
            }
            (DataIntegrityCryptoSuite::Ecdsa2019, Algorithm::ES384) => {
                let (doc_normalized, sigopts_normalized) =
                    urdna2015_normalize(document, proof, context_loader).await?;
                sha384_normalized(doc_normalized, sigopts_normalized)?
            }
            (DataIntegrityCryptoSuite::JcsEcdsa2019, Algorithm::ES256) => {
                let (doc_normalized, sigopts_normalized) = jcs_normalize(document, proof).await?;
                sha256_normalized(doc_normalized, sigopts_normalized)?
            }
            (DataIntegrityCryptoSuite::JcsEcdsa2019, Algorithm::ES384) => {
                let (doc_normalized, sigopts_normalized) = jcs_normalize(document, proof).await?;
                sha384_normalized(doc_normalized, sigopts_normalized)?
            }
            _ => Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch))?,
        })
    }

    async fn prepare_inner(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<(Algorithm, Proof, Vec<u8>), Error> {
        let cryptosuite = match &options.cryptosuite {
            None => DataIntegrityCryptoSuite::pick_from_jwk(key)?
                .first()
                .unwrap()
                .clone(),
            Some(c) => c.clone(),
        };
        if cryptosuite == DataIntegrityCryptoSuite::EcdsaRdfc2019 {
            Self::validate_final_key(key)?;
        }
        let jwa = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != jwa {
                return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
            }
        }
        let mut proof = Proof::new(ProofSuiteType::DataIntegrityProof)
            .with_options(options)
            .with_properties(extra_proof_properties);
        proof.cryptosuite = Some(cryptosuite.clone());
        if cryptosuite == DataIntegrityCryptoSuite::EcdsaRdfc2019 {
            proof.created = options.created;
        } else if !document_has_context(document, CREDENTIALS_V2_CONTEXT)?
            && !document_has_context(document, W3ID_DATA_INTEGRITY_V1_CONTEXT)?
            && !document_has_context(document, W3ID_DATA_INTEGRITY_V2_CONTEXT)?
        {
            proof.context = serde_json::json!([W3ID_DATA_INTEGRITY_V2_CONTEXT]);
        }
        let message =
            Self::jws_payload(&cryptosuite, &jwa, &proof, document, context_loader).await?;
        Ok((jwa, proof, message))
    }

    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let (jwa, mut proof, message) = Self::prepare_inner(
            document,
            options,
            context_loader,
            key,
            extra_proof_properties,
        )
        .await?;
        let sig = ssi_jws::sign_bytes(jwa, &message, key)?;
        let sig_multibase = multibase::encode(multibase::Base::Base58Btc, sig);
        proof.proof_value = Some(sig_multibase);
        Ok(proof)
    }

    pub(crate) async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let (_jwa, proof, message) = Self::prepare_inner(
            document,
            options,
            context_loader,
            public_key,
            extra_proof_properties,
        )
        .await?;
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::Bytes(Base64urlUInt(message)),
        })
    }

    pub(crate) async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<VerificationWarnings, Error> {
        let cryptosuite = proof.cryptosuite.as_ref().ok_or(Error::MissingKey)?;

        let proof_value = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let key = if *cryptosuite == DataIntegrityCryptoSuite::EcdsaRdfc2019 {
            Self::final_verification_key(&resolve_vm(verification_method, resolver).await?)?
        } else {
            resolve_key(verification_method, resolver).await?
        };
        let expected_cryptosuites = DataIntegrityCryptoSuite::pick_from_jwk(&key)?;
        let jwa = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        if !expected_cryptosuites.contains(cryptosuite) {
            return Err(Error::UnexpectedCryptosuite(
                cryptosuite.to_string(),
                format!("{expected_cryptosuites:?}"),
            ));
        }

        // TODO must also match the VM relationship
        if proof.proof_purpose.is_none() {
            return Err(Error::MissingProofPurpose);
        };

        let message = Self::jws_payload(cryptosuite, &jwa, proof, document, context_loader).await?;
        let (base, sig) = multibase::decode(proof_value)?;
        if base != multibase::Base::Base58Btc {
            return Err(Error::ExpectedMultibaseZ);
        }
        match ssi_jws::verify_bytes_warnable(jwa, &message, &key, &sig) {
            Ok(warnings) => Ok(warnings),
            Err(original_error) => {
                let Some(legacy_message) = Self::legacy_rdfc_jws_payload(
                    cryptosuite,
                    &jwa,
                    proof,
                    document,
                    context_loader,
                )
                .await?
                else {
                    return Err(original_error.into());
                };
                Ok(ssi_jws::verify_bytes_warnable(
                    jwa,
                    &legacy_message,
                    &key,
                    &sig,
                )?)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serde_defaults_to_eddsa_rdfc_2022() {
        let res = serde_json::to_string(&DataIntegrityCryptoSuite::EddsaRdfc2022).unwrap();
        assert_eq!(res, "\"eddsa-rdfc-2022\"".to_string());
    }

    #[test]
    fn serde_supports_legacy_eddsa_2022() {
        let cryptosuite = DataIntegrityCryptoSuite::try_from("eddsa-2022").unwrap();
        assert_eq!(cryptosuite, DataIntegrityCryptoSuite::Eddsa2022);
    }

    #[test]
    fn final_optional_created_respects_cutoffs_for_present_dates() {
        let cutoff = "2024-01-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let options = LinkedDataProofOptions {
            created: Some(cutoff),
            ..Default::default()
        };
        let mut proof = Proof::new(ProofSuiteType::DataIntegrityProof).with_options(&options);
        proof.cryptosuite = Some(DataIntegrityCryptoSuite::EcdsaRdfc2019);
        assert!(proof.matches_options(&options));
        proof.created = Some(cutoff + chrono::Duration::seconds(1));
        assert!(!proof.matches_options(&options));
        proof.created = None;
        assert!(proof.matches_options(&options));
        proof.cryptosuite = Some(DataIntegrityCryptoSuite::Ecdsa2019);
        assert!(!proof.matches_options(&options));
        assert!(serde_json::from_value::<Proof>(serde_json::json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "ecdsa-rdfc-2019",
            "created": "not-a-date"
        }))
        .is_err());
    }

    #[cfg(feature = "secp256r1")]
    mod final_p256 {
        use super::*;
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        struct Document(Value);

        #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
        impl LinkedDataDocument for Document {
            fn get_contexts(&self) -> Result<Option<String>, Error> {
                self.0
                    .get("@context")
                    .map(serde_json::to_string)
                    .transpose()
                    .map_err(Into::into)
            }

            fn to_value(&self) -> Result<Value, Error> {
                Ok(self.0.clone())
            }

            async fn to_dataset_for_signing(
                &self,
                _parent: Option<&(dyn LinkedDataDocument + Sync)>,
                loader: &mut ContextLoader,
            ) -> Result<ssi_json_ld::rdf::DataSet, Error> {
                Ok(ssi_json_ld::json_to_dataset(
                    json_syntax::to_value_with(self.0.clone(), Default::default).unwrap(),
                    loader,
                    None,
                )
                .await?)
            }
        }

        fn key() -> JWK {
            serde_json::from_str(include_str!("../../../tests/secp256r1-2021-03-18.json")).unwrap()
        }

        fn multikey(bytes: &[u8], base: multibase::Base) -> ssi_dids::VerificationMethodMap {
            serde_json::from_value(serde_json::json!({
                "id": "did:example:holder#key",
                "controller": "did:example:holder",
                "type": "Multikey",
                "publicKeyMultibase": multibase::encode(base, bytes)
            }))
            .unwrap()
        }

        #[test]
        fn final_key_requires_p256_and_es256() {
            let mut key = key();
            assert!(DataIntegrityProof::validate_final_key(&key).is_ok());
            key.algorithm = Some(Algorithm::ES384);
            assert!(matches!(
                DataIntegrityProof::validate_final_key(&key),
                Err(Error::JWS(_))
            ));
            key.algorithm = Some(Algorithm::ES256);
            let ssi_jwk::Params::EC(params) = &mut key.params else {
                unreachable!()
            };
            params.curve = Some("P-384".into());
            assert!(matches!(
                DataIntegrityProof::validate_final_key(&key),
                Err(Error::UnsupportedCurve)
            ));
        }

        #[test]
        fn final_multikey_requires_public_codec_base_and_valid_compressed_point() {
            let key = key().to_public();
            let ssi_jwk::Params::EC(params) = &key.params else {
                unreachable!()
            };
            let public = p256::PublicKey::try_from(params).unwrap();
            let mut bytes = vec![0x80, 0x24];
            bytes.extend_from_slice(public.to_encoded_point(true).as_bytes());
            assert!(DataIntegrityProof::final_verification_key(&multikey(
                &bytes,
                multibase::Base::Base58Btc
            ))
            .unwrap()
            .equals_public(&key));
            assert!(matches!(
                DataIntegrityProof::final_verification_key(&multikey(
                    &bytes,
                    multibase::Base::Base64Url
                )),
                Err(Error::ExpectedMultibaseZ)
            ));
            let mut wrong_codec = bytes.clone();
            wrong_codec[0] = 0x81; // p384-pub, not p256-pub.
            assert!(DataIntegrityProof::final_verification_key(&multikey(
                &wrong_codec,
                multibase::Base::Base58Btc
            ))
            .is_err());
            let mut uncompressed = vec![0x80, 0x24];
            uncompressed.extend_from_slice(public.to_encoded_point(false).as_bytes());
            assert!(DataIntegrityProof::final_verification_key(&multikey(
                &uncompressed,
                multibase::Base::Base58Btc
            ))
            .is_err());
            assert!(DataIntegrityProof::final_verification_key(&multikey(
                &bytes[..34],
                multibase::Base::Base58Btc
            ))
            .is_err());
            bytes[3..].fill(0xff); // An x-coordinate outside the field.
            assert!(DataIntegrityProof::final_verification_key(&multikey(
                &bytes,
                multibase::Base::Base58Btc
            ))
            .is_err());
        }

        #[async_std::test]
        async fn final_configuration_requires_actual_context_and_cryptosuite_datatype() {
            let options = LinkedDataProofOptions {
                cryptosuite: Some(DataIntegrityCryptoSuite::EcdsaRdfc2019),
                created: None,
                verification_method: Some(crate::URI::String("did:example:holder#key".into())),
                ..Default::default()
            };
            let key = key();
            let mut loader = ContextLoader::default();
            for (value, missing) in [
                (serde_json::json!({}), true),
                (serde_json::json!({"@context": null}), false),
                (serde_json::json!({"@context": 42}), false),
            ] {
                let result = DataIntegrityProof::prepare(
                    &Document(value),
                    &options,
                    &mut loader,
                    &key,
                    None,
                )
                .await;
                if missing {
                    assert!(matches!(result, Err(Error::MissingContext)));
                } else {
                    assert!(matches!(result, Err(Error::InvalidContext)));
                }
            }
            let mut document = serde_json::json!({
                "@context": {
                    "type": "@type",
                    "DataIntegrityProof": "https://w3id.org/security#DataIntegrityProof",
                    "proofPurpose": {"@id": "https://w3id.org/security#proofPurpose", "@type": "@vocab"},
                    "assertionMethod": "https://w3id.org/security#assertionMethod",
                    "verificationMethod": {"@id": "https://w3id.org/security#verificationMethod", "@type": "@id"},
                    "cryptosuite": {"@id": "https://w3id.org/security#cryptosuite", "@type": "https://w3id.org/security#cryptosuiteString"}
                }
            });
            let prepared = DataIntegrityProof::prepare(
                &Document(document.clone()),
                &options,
                &mut loader,
                &key,
                None,
            )
            .await
            .unwrap();
            assert_eq!(prepared.proof.created, None);
            document["@context"]["cryptosuite"]["@type"] =
                Value::String("http://www.w3.org/2001/XMLSchema#string".into());
            assert!(matches!(
                DataIntegrityProof::prepare(&Document(document), &options, &mut loader, &key, None)
                    .await,
                Err(Error::InconsistentProof(_))
            ));
        }
    }
}
