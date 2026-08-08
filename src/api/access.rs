use crate::mdm::ServiceTokenEnrollment;
use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderValue, LOCATION};
use reqwest::redirect::Policy;
use reqwest::{Client, RequestBuilder, Url};

const ACCESS_CLIENT_ID_HEADER: &str = "CF-Access-Client-Id";
const ACCESS_CLIENT_SECRET_HEADER: &str = "CF-Access-Client-Secret";

pub async fn acquire_service_token_jwt(config: &ServiceTokenEnrollment) -> Result<String> {
    let host = format!("{}.cloudflareaccess.com", config.organization());
    let url = Url::parse(&format!("https://{host}/warp"))
        .context("failed to construct Cloudflare Access enrollment URL")?;
    let client = Client::builder()
        .redirect(Policy::none())
        .build()
        .context("failed to create Cloudflare Access client")?;
    let response = service_token_request(&client, url, config)
        .send()
        .await
        .context("failed to request Cloudflare Access enrollment JWT")?;
    if !response.status().is_redirection() {
        return Err(anyhow!(
            "Cloudflare Access enrollment returned {}; expected a WARP callback redirect",
            response.status()
        ));
    }
    let location = response
        .headers()
        .get(LOCATION)
        .ok_or_else(|| anyhow!("Cloudflare Access enrollment redirect has no Location header"))?;
    parse_callback(location, &host)
}

fn service_token_request(
    client: &Client,
    url: Url,
    config: &ServiceTokenEnrollment,
) -> RequestBuilder {
    client
        .get(url)
        .header(ACCESS_CLIENT_ID_HEADER, config.client_id())
        .header(ACCESS_CLIENT_SECRET_HEADER, config.client_secret())
}

fn parse_callback(location: &HeaderValue, expected_host: &str) -> Result<String> {
    let location = location
        .to_str()
        .context("Cloudflare Access returned a non-UTF-8 Location header")?;
    let callback = Url::parse(location)
        .context("failed to parse Cloudflare Access enrollment callback URL")?;
    if matches!(callback.scheme(), "http" | "https") {
        return Err(anyhow!(
            "Cloudflare Access did not accept the service token; verify that the MDM token is selected by a Service Auth Device Enrollment policy"
        ));
    }
    if callback.scheme() != "com.cloudflare.warp"
        || callback.host_str() != Some(expected_host)
        || callback.port().is_some()
        || !callback.username().is_empty()
        || callback.password().is_some()
        || callback.path() != "/auth"
        || callback.fragment().is_some()
    {
        return Err(anyhow!(
            "Cloudflare Access returned an unexpected enrollment callback origin or path"
        ));
    }
    let mut tokens = callback
        .query_pairs()
        .filter_map(|(key, value)| (key == "token").then(|| value.into_owned()));
    let token = tokens
        .next()
        .ok_or_else(|| anyhow!("Cloudflare Access enrollment callback has no token parameter"))?;
    if tokens.next().is_some() {
        return Err(anyhow!(
            "Cloudflare Access callback has multiple token parameters"
        ));
    }
    if token.is_empty()
        || token.len() > 64 * 1024
        || token.contains(['\r', '\n'])
        || token.split('.').count() != 3
    {
        return Err(anyhow!(
            "Cloudflare Access returned an invalid enrollment JWT"
        ));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::{parse_callback, service_token_request};
    use crate::mdm::ServiceTokenEnrollment;
    use reqwest::header::HeaderValue;
    use reqwest::{Client, Url};

    fn config() -> ServiceTokenEnrollment {
        ServiceTokenEnrollment::from_mdm_xml(
            "<dict><key>organization</key><string>example</string><key>auth_client_id</key><string>id.access</string><key>auth_client_secret</key><string>secret</string></dict>",
        )
        .unwrap()
    }

    #[test]
    fn request_sends_service_credentials_to_the_access_origin() {
        let request = service_token_request(
            &Client::new(),
            Url::parse("https://example.cloudflareaccess.com/warp").unwrap(),
            &config(),
        )
        .build()
        .unwrap();
        assert_eq!(request.headers()["CF-Access-Client-Id"], "id.access");
        assert_eq!(request.headers()["CF-Access-Client-Secret"], "secret");
        assert!(!request.headers().contains_key("CF-Access-Jwt-Assertion"));
        assert!(!request.headers().contains_key("CF-Client-Version"));
        assert!(!request.headers().contains_key("User-Agent"));
    }

    #[test]
    fn callback_is_origin_bound_and_rejects_interactive_login() {
        let callback = HeaderValue::from_static(
            "com.cloudflare.warp://example.cloudflareaccess.com/auth?token=header.payload.signature",
        );
        assert_eq!(
            parse_callback(&callback, "example.cloudflareaccess.com").unwrap(),
            "header.payload.signature"
        );
        let login = HeaderValue::from_static(
            "https://example.cloudflareaccess.com/cdn-cgi/access/login/example.cloudflareaccess.com",
        );
        assert!(parse_callback(&login, "example.cloudflareaccess.com").is_err());
        for wrong in [
            "com.cloudflare.warp://wrong.example/auth?token=header.payload.signature",
            "com.cloudflare.warp://example.cloudflareaccess.com:443/auth?token=header.payload.signature",
            "com.cloudflare.warp://user@example.cloudflareaccess.com/auth?token=header.payload.signature",
            "com.cloudflare.warp://example.cloudflareaccess.com/auth?token=header.payload.signature#fragment",
            "com.cloudflare.warp://example.cloudflareaccess.com/auth?token=one.two.three&token=four.five.six",
        ] {
            assert!(parse_callback(
                &HeaderValue::from_str(wrong).unwrap(),
                "example.cloudflareaccess.com"
            )
            .is_err());
        }
    }
}
