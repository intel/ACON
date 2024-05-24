use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod,
    CoreDeviceAuthorizationResponse, CoreGrantType, CoreJsonWebKey, CoreJsonWebKeyType,
    CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AdditionalProviderMetadata, AuthType, ClientId, ClientSecret, DeviceAuthorizationUrl,
    IssuerUrl, Nonce, NonceVerifier, ProviderMetadata,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DeviceEndpointProviderMetadata {
    device_authorization_endpoint: DeviceAuthorizationUrl,
}
impl AdditionalProviderMetadata for DeviceEndpointProviderMetadata {}
type DeviceProviderMetadata = ProviderMetadata<
    DeviceEndpointProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

const TIME_OUT: u64 = 300;
const GOOGLE_ISSUE_URL: &str = "https://accounts.google.com";
const ERR_IDP_ID_TOKEN_NOT_RETURN: &str = "Idp server doesn't return an ID token";
const ERR_IDP_INVALID_OPENID_USER: &str = "Invalid openid user from Idp server";

struct EmptyNonce;

impl NonceVerifier for &EmptyNonce {
    fn verify(self, _: Option<&Nonce>) -> Result<(), String> {
        Ok(())
    }
}

pub async fn verify_id_token(
    client_id: &str,
    client_secret: &str,
    device_code: &str,
    expires_in: u64,
    timeout: Option<i64>,
    openid_user: &Option<String>,
) -> Result<Vec<u8>> {
    let client_id = ClientId::new(client_id.into());
    let client_secret = ClientSecret::new(client_secret.into());
    let issuer_url = IssuerUrl::new(GOOGLE_ISSUE_URL.into())?;

    let provider_metadata =
        DeviceProviderMetadata::discover_async(issuer_url, async_http_client).await?;

    let device_authorization_endpoint = provider_metadata
        .additional_metadata()
        .device_authorization_endpoint
        .clone();

    let client =
        CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            .set_device_authorization_uri(device_authorization_endpoint.clone())
            .set_auth_type(AuthType::RequestBody);

    let details: CoreDeviceAuthorizationResponse = serde_json::from_str(
        format!(
            r#"{{
            "device_code": "{}",
            "user_code": "{}",
            "verification_uri": "{}",
            "expires_in": {}
        }}"#,
            device_code,
            device_code,
            device_authorization_endpoint.as_str(),
            expires_in
        )
        .as_str(),
    )?;

    let token = client
        .exchange_device_access_token(&details)
        .request_async(
            async_http_client,
            tokio::time::sleep,
            Some(std::time::Duration::from_secs(TIME_OUT)),
        )
        .await?;
    let id_token_claims = token
        .extra_fields()
        .id_token()
        .ok_or(anyhow!(ERR_IDP_ID_TOKEN_NOT_RETURN))?
        .claims(&client.id_token_verifier(), &EmptyNonce)?;

    match id_token_claims.email_verified() {
        Some(true) => (),
        _ => return Err(anyhow!(ERR_IDP_INVALID_OPENID_USER)),
    }

    if id_token_claims.email().map(|e| e.to_string()) != openid_user.clone() {
        return Err(anyhow!(ERR_IDP_INVALID_OPENID_USER));
    }

    Ok(match timeout {
        Some(t) => (Utc::now() + Duration::seconds(t)).timestamp(),
        None => id_token_claims.expiration().timestamp(),
    }
    .to_ne_bytes()
    .to_vec())
}
