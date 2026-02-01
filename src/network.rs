use anyhow::{Context, Result};

// ============================================================================
// Network Configuration
// ============================================================================

#[derive(Debug, Clone)]
pub(crate) struct NetworkConfig {
    pub(crate) headers: Vec<String>,
    pub(crate) retries: usize,
    pub(crate) script_client: reqwest::Client, // Respects --insecure for script downloads
    pub(crate) api_client: reqwest::Client,    // Always enforces TLS for API calls
}

impl NetworkConfig {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        timeout: u64,
        max_redirects: usize,
        insecure: bool,
        no_proxy: bool,
        proxy: Option<String>,
        system_proxy: bool,
        user_agent: Option<String>,
        headers: Vec<String>,
        retries: usize,
    ) -> Result<Self> {
        // Build script client (respects --insecure)
        let mut script_builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout))
            .redirect(if max_redirects > 0 {
                reqwest::redirect::Policy::limited(max_redirects)
            } else {
                reqwest::redirect::Policy::none()
            });

        if insecure {
            script_builder = script_builder.danger_accept_invalid_certs(true);
        }

        script_builder = Self::apply_proxy(script_builder, no_proxy, &proxy, system_proxy)?;
        script_builder = Self::apply_user_agent(script_builder, &user_agent);
        let script_client = script_builder
            .build()
            .context("Failed to build script HTTP client")?;

        // Build API client (always secure TLS)
        let mut api_builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout))
            .redirect(if max_redirects > 0 {
                reqwest::redirect::Policy::limited(max_redirects)
            } else {
                reqwest::redirect::Policy::none()
            });

        api_builder = Self::apply_proxy(api_builder, no_proxy, &proxy, system_proxy)?;
        api_builder = Self::apply_user_agent(api_builder, &user_agent);
        let api_client = api_builder
            .build()
            .context("Failed to build API HTTP client")?;

        Ok(Self {
            headers,
            retries,
            script_client,
            api_client,
        })
    }

    fn apply_proxy(
        mut builder: reqwest::ClientBuilder,
        no_proxy: bool,
        proxy: &Option<String>,
        system_proxy: bool,
    ) -> Result<reqwest::ClientBuilder> {
        if no_proxy {
            builder = builder.no_proxy();
        } else if let Some(ref proxy_url) = proxy {
            // Validate proxy URL
            let parsed = reqwest::Url::parse(proxy_url).context("Invalid proxy URL")?;
            let scheme = parsed.scheme();
            if !matches!(scheme, "http" | "https" | "socks5" | "socks5h") {
                anyhow::bail!("Invalid proxy scheme: {}. Only http, https, socks5, and socks5h are supported.", scheme);
            }
            let p = reqwest::Proxy::all(proxy_url).context("Invalid proxy URL")?;
            builder = builder.proxy(p);
        } else if system_proxy {
            // System proxy is enabled by default in reqwest
        }
        Ok(builder)
    }

    fn apply_user_agent(
        mut builder: reqwest::ClientBuilder,
        user_agent: &Option<String>,
    ) -> reqwest::ClientBuilder {
        if let Some(ref ua) = user_agent {
            builder = builder.user_agent(ua.clone());
        } else {
            builder = builder.user_agent(format!("scurl/{}", env!("CARGO_PKG_VERSION")));
        }
        builder
    }

    pub(crate) fn parse_headers(&self) -> Result<Vec<(String, String)>> {
        let mut parsed = Vec::new();
        for header in &self.headers {
            if let Some((key, value)) = header.split_once(':') {
                parsed.push((key.trim().to_string(), value.trim().to_string()));
            } else {
                anyhow::bail!("Invalid header format: '{}'. Use 'Key: Value'", header);
            }
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_config_parse_headers() {
        let client = reqwest::Client::new();
        let config = NetworkConfig {
            headers: vec![
                "Authorization: Bearer token".to_string(),
                "X-Custom: value".to_string(),
            ],
            retries: 3,
            script_client: client.clone(),
            api_client: client,
        };

        let parsed = config.parse_headers().unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[0],
            ("Authorization".to_string(), "Bearer token".to_string())
        );
        assert_eq!(parsed[1], ("X-Custom".to_string(), "value".to_string()));
    }

    #[test]
    fn test_network_config_parse_headers_invalid() {
        let client = reqwest::Client::new();
        let config = NetworkConfig {
            headers: vec!["InvalidHeader".to_string()],
            retries: 3,
            script_client: client.clone(),
            api_client: client,
        };

        assert!(config.parse_headers().is_err());
    }
}
