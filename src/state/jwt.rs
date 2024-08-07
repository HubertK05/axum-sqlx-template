use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(Clone)]
pub struct JwtKeys {
    pub access: JwtKeyPair,
    pub refresh: JwtKeyPair,
}

impl JwtKeys {
    pub fn from_eddsa() -> Self {
        let access =
            JwtKeyPair::from_eddsa_path(JWT_ACCESS_ENCODING_KEY_PATH, JWT_ACCESS_DECODING_KEY_PATH);
        let refresh = JwtKeyPair::from_eddsa_path(
            JWT_REFRESH_ENCODING_KEY_PATH,
            JWT_REFRESH_DECODING_KEY_PATH,
        );
        Self { access, refresh }
    }
}

#[derive(Clone)]
pub struct JwtKeyPair {
    header: Header,
    validation: Validation,
    encoding: EncodingKey,
    decoding: DecodingKey,
}

const JWT_ACCESS_ENCODING_KEY_PATH: &str = "./keys/jwt_access_private_key.pem";
const JWT_ACCESS_DECODING_KEY_PATH: &str = "./keys/jwt_access_public_key.pem";
const JWT_REFRESH_ENCODING_KEY_PATH: &str = "./keys/jwt_refresh_private_key.pem";
const JWT_REFRESH_DECODING_KEY_PATH: &str = "./keys/jwt_refresh_public_key.pem";

impl JwtKeyPair {
    fn from_eddsa_path(encoding_path: &str, decoding_path: &str) -> Self {
        let encoding_pem = std::fs::read(encoding_path).unwrap();
        let decoding_pem = std::fs::read(decoding_path).unwrap();
        let encoding = EncodingKey::from_ed_pem(&encoding_pem).unwrap();
        let decoding = DecodingKey::from_ed_pem(&decoding_pem).unwrap();
        let header = Header::new(Algorithm::EdDSA);
        let validation = Validation::new(Algorithm::EdDSA);
        Self {
            header,
            validation,
            encoding,
            decoding,
        }
    }

    pub fn encode<T: Serialize>(&self, claims: &T) -> jsonwebtoken::errors::Result<String> {
        jsonwebtoken::encode(&self.header, claims, &self.encoding)
    }

    pub fn decode<T: DeserializeOwned>(&self, token: &str) -> jsonwebtoken::errors::Result<T> {
        jsonwebtoken::decode::<T>(token, &self.decoding, &self.validation).map(|data| data.claims)
    }
}
