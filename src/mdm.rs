use anyhow::{anyhow, Context, Result};
use quick_xml::escape::unescape;
use quick_xml::events::Event;
use quick_xml::name::QName;
use quick_xml::Reader;

pub struct ServiceTokenEnrollment {
    organization: String,
    client_id: String,
    client_secret: String,
}

impl ServiceTokenEnrollment {
    pub fn from_mdm_xml(xml: &str) -> Result<Self> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);
        let mut root_open = false;
        let mut root_closed = false;
        let mut pending_key = None;
        let mut organization = None;
        let mut client_id = None;
        let mut client_secret = None;

        loop {
            match reader.read_event().context("failed to parse MDM XML")? {
                Event::Decl(_) | Event::Comment(_) => {}
                Event::DocType(_) => return Err(anyhow!("MDM XML document types are not allowed")),
                Event::Start(element) if !root_open && !root_closed => {
                    if element.name() != QName(b"dict") {
                        return Err(anyhow!("MDM XML root element must be <dict>"));
                    }
                    root_open = true;
                }
                Event::Start(element) if root_open => {
                    if element.name() == QName(b"key") {
                        if pending_key.is_some() {
                            return Err(anyhow!("MDM key has no value"));
                        }
                        let key = reader
                            .read_text(QName(b"key"))
                            .context("failed to read MDM key")?;
                        let key = key.decode().context("failed to decode MDM key text")?;
                        let key = unescape(&key)
                            .context("failed to decode MDM key entities")?
                            .into_owned();
                        pending_key = Some(key.trim().to_string());
                        continue;
                    }
                    let key = pending_key
                        .take()
                        .ok_or_else(|| anyhow!("MDM value has no preceding key"))?;
                    let required = is_required_key(&key);
                    if element.name() != QName(b"string") {
                        reader
                            .read_to_end(element.name())
                            .context("failed to skip unsupported MDM value")?;
                        if required {
                            return Err(anyhow!("MDM key '{key}' must have a <string> value"));
                        }
                        continue;
                    }
                    let value = reader
                        .read_text(QName(b"string"))
                        .context("failed to read MDM string value")?;
                    let value = value.decode().context("failed to decode MDM string text")?;
                    let value = unescape(&value)
                        .context("failed to decode MDM string entities")?
                        .into_owned();
                    match key.as_str() {
                        "organization" => set_once(&mut organization, value, &key)?,
                        "auth_client_id" => set_once(&mut client_id, value, &key)?,
                        "auth_client_secret" => set_once(&mut client_secret, value, &key)?,
                        _ => {}
                    }
                }
                Event::Empty(_) if root_open => {
                    let key = pending_key
                        .take()
                        .ok_or_else(|| anyhow!("MDM value has no preceding key"))?;
                    if is_required_key(&key) {
                        return Err(anyhow!("MDM key '{key}' must have a <string> value"));
                    }
                }
                Event::End(element) if root_open && element.name() == QName(b"dict") => {
                    if pending_key.is_some() {
                        return Err(anyhow!("MDM key has no value"));
                    }
                    root_open = false;
                    root_closed = true;
                }
                Event::Text(text) => {
                    if !text.as_ref().iter().all(u8::is_ascii_whitespace) {
                        return Err(anyhow!("unexpected text outside MDM values"));
                    }
                }
                Event::Eof => break,
                Event::Start(_) | Event::Empty(_) | Event::End(_) => {
                    return Err(anyhow!("unsupported nested MDM XML structure"));
                }
                _ => return Err(anyhow!("unsupported MDM XML event")),
            }
        }
        if root_open || !root_closed {
            return Err(anyhow!("MDM XML does not contain a complete <dict>"));
        }
        let organization = required(organization, "organization")?;
        let client_id = required(client_id, "auth_client_id")?;
        let client_secret = required(client_secret, "auth_client_secret")?;
        validate_organization(&organization)?;
        validate_line("auth_client_id", &client_id, 512)?;
        validate_line("auth_client_secret", &client_secret, 4096)?;
        if !client_id.ends_with(".access") {
            return Err(anyhow!(
                "MDM auth_client_id is not a Cloudflare Access service-token client ID"
            ));
        }
        Ok(Self {
            organization,
            client_id,
            client_secret,
        })
    }

    pub fn organization(&self) -> &str {
        &self.organization
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }
}

fn is_required_key(key: &str) -> bool {
    matches!(
        key,
        "organization" | "auth_client_id" | "auth_client_secret"
    )
}

fn set_once(slot: &mut Option<String>, value: String, key: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        return Err(anyhow!("MDM key '{key}' is duplicated"));
    }
    Ok(())
}

fn required(value: Option<String>, key: &str) -> Result<String> {
    let value = value.ok_or_else(|| anyhow!("MDM key '{key}' is required"))?;
    if value.trim().is_empty() {
        return Err(anyhow!("MDM key '{key}' must not be empty"));
    }
    Ok(value)
}

fn validate_organization(value: &str) -> Result<()> {
    if value.len() > 63
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(anyhow!(
            "MDM organization must be a single valid Cloudflare Zero Trust team-name label"
        ));
    }
    Ok(())
}

fn validate_line(name: &str, value: &str, max_len: usize) -> Result<()> {
    if value.len() > max_len {
        return Err(anyhow!("MDM {name} exceeds {max_len} bytes"));
    }
    if value.contains(['\r', '\n']) {
        return Err(anyhow!("MDM {name} must contain exactly one line"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ServiceTokenEnrollment;

    const VALID: &str = r#"<dict>
      <key>auth_client_id</key><string>example.access</string>
      <key>auth_client_secret</key><string>secret&amp;value</string>
      <key>auto_connect</key><integer>1</integer>
      <key>onboarding</key><false/>
      <key>organization</key><string>example-team</string>
      <key>service_mode</key><string>warp</string>
    </dict>"#;

    #[test]
    fn parses_documented_mdm_fragment_and_ignores_optional_values() {
        let config = ServiceTokenEnrollment::from_mdm_xml(VALID).unwrap();
        assert_eq!(config.organization(), "example-team");
        assert_eq!(config.client_id(), "example.access");
        assert_eq!(config.client_secret(), "secret&value");
    }

    #[test]
    fn rejects_missing_or_non_string_required_values() {
        assert!(ServiceTokenEnrollment::from_mdm_xml(
            "<dict><key>organization</key><string>team</string></dict>"
        )
        .is_err());
        assert!(ServiceTokenEnrollment::from_mdm_xml("<dict><key>organization</key><integer>1</integer><key>auth_client_id</key><string>x.access</string><key>auth_client_secret</key><string>s</string></dict>").is_err());
    }

    #[test]
    fn rejects_organization_that_can_change_the_access_origin() {
        assert!(ServiceTokenEnrollment::from_mdm_xml("<dict><key>organization</key><string>team.example</string><key>auth_client_id</key><string>x.access</string><key>auth_client_secret</key><string>s</string></dict>").is_err());
    }

    #[test]
    fn rejects_document_types() {
        assert!(ServiceTokenEnrollment::from_mdm_xml(
            "<!DOCTYPE dict><dict><key>organization</key><string>team</string><key>auth_client_id</key><string>x.access</string><key>auth_client_secret</key><string>s</string></dict>"
        )
        .is_err());
    }
}
