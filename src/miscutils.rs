use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use std::convert::Infallible;
use std::net::IpAddr;

#[derive(Debug)]
pub struct ForwardedFor(Vec<IpAddr>);

impl ForwardedFor {
    fn ips_from_header_value(header_value: &str) -> Vec<IpAddr> {
        header_value
            .split(',')
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .collect()
    }

    pub fn client_ip(&self) -> Option<&IpAddr> {
        self.0.first()
    }
}
#[async_trait]
impl<S> FromRequestParts<S> for ForwardedFor
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|hv| hv.to_str().ok())
                .flat_map(Self::ips_from_header_value)
                .collect(),
        ))
    }
}
