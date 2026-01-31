# Network & Proxy Configuration

scurl supports comprehensive network configuration options for corporate environments, proxies, and special network setups.

## Quick Examples

```bash
# Use HTTP proxy
scurl --proxy http://proxy.example.com:8080 https://example.com/install.sh

# Custom timeout and retries
scurl --timeout 60 --retries 5 https://slow-server.com/script.sh

# Ignore SSL errors (insecure!)
scurl --insecure https://self-signed.example.com/install.sh

# Custom headers
scurl -H "Authorization: Bearer token123" -H "X-Custom: value" https://api.example.com/script.sh

# Use system proxy + custom User-Agent
scurl --system-proxy -A "MyApp/1.0" https://example.com/install.sh
```

## Network Options

### Proxy Configuration

#### `--proxy <URL>` or `-x <URL>`
Set HTTP/HTTPS proxy for all requests.

```bash
# HTTP proxy
scurl --proxy http://proxy.company.com:8080 URL

# HTTPS proxy  
scurl --proxy https://secure-proxy.company.com:8443 URL

# Proxy with authentication
scurl --proxy http://user:pass@proxy.company.com:8080 URL

# Environment variable (alternative)
export HTTPS_PROXY=http://proxy.company.com:8080
scurl URL
```

#### `--system-proxy`
Use system proxy settings (enabled by default in most environments).

```bash
scurl --system-proxy URL
```

#### `--no-proxy`
Disable all proxy settings, even if environment variables are set.

```bash
# Ignore HTTP_PROXY and HTTPS_PROXY env vars
scurl --no-proxy URL
```

### Timeout & Retries

#### `--timeout <SECONDS>` or `-t <SECONDS>`
Set request timeout in seconds (default: 30).

```bash
# 60 second timeout
scurl --timeout 60 URL

# Fast timeout for quick check
scurl --timeout 5 URL
```

#### `--retries <COUNT>`
Number of retry attempts on network failure (default: 3).

```bash
# Retry up to 5 times
scurl --retries 5 URL

# No retries (fail immediately)
scurl --retries 1 URL

# More retries for unreliable networks
scurl --retries 10 URL
```

Retries use exponential backoff: 1s, 2s, 3s, etc.

### Redirects

#### `--max-redirects <COUNT>`
Maximum HTTP redirects to follow (default: 10).

```bash
# Allow more redirects
scurl --max-redirects 20 URL

# Disable redirects entirely
scurl --max-redirects 0 URL
```

### SSL/TLS Configuration

#### `--insecure` or `-k`
Disable SSL certificate verification (dangerous!).

```bash
# Accept self-signed certificates
scurl --insecure https://self-signed.local/script.sh
```

⚠️ **Warning**: Only use this for testing! It makes you vulnerable to man-in-the-middle attacks.

**When to use:**
- Internal corporate servers with self-signed certs
- Development/testing environments
- Never in production!

### Headers

#### `--header <HEADER>` or `-H <HEADER>`
Add custom HTTP headers. Can be used multiple times.

```bash
# Single header
scurl -H "Authorization: Bearer token123" URL

# Multiple headers
scurl \
  -H "Authorization: Bearer token123" \
  -H "X-API-Key: secret456" \
  -H "Accept: application/json" \
  URL
```

**Format**: `Key: Value` (note the colon and space)

Common use cases:
```bash
# API authentication
scurl -H "Authorization: Bearer $TOKEN" URL

# Custom accept type
scurl -H "Accept: text/plain" URL

# Request ID for tracing
scurl -H "X-Request-ID: $REQUEST_ID" URL
```

#### `--user-agent <STRING>` or `-A <STRING>`
Set custom User-Agent header.

```bash
# Custom user agent
scurl -A "MyCompany-DeployBot/2.0" URL

# Mimic browser
scurl -A "Mozilla/5.0 (compatible)" URL
```

Default: `scurl/0.1.0`

## Environment Variables

scurl respects standard proxy environment variables:

```bash
# HTTPS proxy (preferred)
export HTTPS_PROXY=http://proxy.example.com:8080

# HTTP proxy (fallback)
export HTTP_PROXY=http://proxy.example.com:8080

# No proxy for certain domains
export NO_PROXY=localhost,127.0.0.1,.local

# Use scurl normally - proxy is auto-detected
scurl https://example.com/install.sh
```

**Precedence**:
1. `--proxy` flag (highest priority)
2. `HTTPS_PROXY` environment variable
3. `HTTP_PROXY` environment variable
4. System proxy settings

**Override with flags**:
```bash
# Ignore env vars
scurl --no-proxy URL

# Use different proxy
scurl --proxy http://other-proxy.com:8080 URL
```

## Corporate/Enterprise Environments

### Behind Corporate Proxy

```bash
# Set proxy in your shell profile (~/.bashrc or ~/.zshrc)
export HTTPS_PROXY=http://proxy.corporate.com:8080
export HTTP_PROXY=http://proxy.corporate.com:8080

# Or use flag each time
alias scurl='scurl --proxy http://proxy.corporate.com:8080'
```

### With Proxy Authentication

```bash
# Embed credentials in proxy URL
scurl --proxy http://username:password@proxy.com:8080 URL

# Or use environment variable
export HTTPS_PROXY=http://username:password@proxy.com:8080
```

### Self-Signed Certificates

```bash
# Accept internal CA (insecure flag)
scurl --insecure https://internal-server.corp/script.sh

# Better: Add corporate CA to system trust store instead
```

### Custom Headers for Internal APIs

```bash
# Internal API requiring special headers
scurl \
  -H "X-Corp-Auth: $CORP_TOKEN" \
  -H "X-Environment: production" \
  https://internal-api.corp/deploy.sh
```

## Combining Options

All network options can be combined:

```bash
scurl \
  --proxy http://proxy.company.com:8080 \
  --timeout 60 \
  --retries 5 \
  --insecure \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Request-ID: $ID" \
  -A "DeployBot/1.0" \
  --max-redirects 20 \
  https://example.com/install.sh
```

## Troubleshooting

### Connection Refused
```bash
# Try with increased timeout
scurl --timeout 60 --retries 5 URL
```

### Proxy Issues
```bash
# Check proxy is accessible
curl -x http://proxy.example.com:8080 https://google.com

# Try without proxy
scurl --no-proxy URL

# Check environment variables
echo $HTTPS_PROXY
echo $HTTP_PROXY
```

### SSL Certificate Errors
```bash
# Temporarily bypass (testing only!)
scurl --insecure URL

# Better: Add CA certificate to system trust store
# macOS: Keychain Access
# Linux: /etc/ssl/certs/
# Windows: Certificate Manager
```

### Timeout Too Short
```bash
# Increase timeout for slow networks
scurl --timeout 120 URL

# Infinite timeout (not recommended)
scurl --timeout 999999 URL
```

### Too Many Redirects
```bash
# Increase redirect limit
scurl --max-redirects 20 URL

# Check for redirect loops
curl -v URL 2>&1 | grep Location
```

## Advanced Scenarios

### CI/CD with Corporate Proxy

```yaml
# GitHub Actions
- name: Install tool with scurl
  env:
    HTTPS_PROXY: ${{ secrets.CORPORATE_PROXY }}
  run: |
    scurl --auto-execute https://example.com/install.sh
```

### Docker Container with Proxy

```dockerfile
ENV HTTPS_PROXY=http://proxy.company.com:8080
RUN scurl https://example.com/install.sh
```

### Kubernetes with Proxy

```yaml
env:
  - name: HTTPS_PROXY
    value: "http://proxy.company.com:8080"
  - name: NO_PROXY
    value: "localhost,127.0.0.1,.svc.cluster.local"
```

### Testing Different Proxies

```bash
# Test direct connection
time scurl --no-proxy URL

# Test proxy 1
time scurl --proxy http://proxy1.com:8080 URL

# Test proxy 2  
time scurl --proxy http://proxy2.com:8080 URL

# Compare speeds
```

## Performance Tips

1. **Increase retries for unreliable networks**
   ```bash
   scurl --retries 10 URL
   ```

2. **Shorter timeout for quick failures**
   ```bash
   scurl --timeout 10 URL
   ```

3. **Disable redirects for speed**
   ```bash
   scurl --max-redirects 0 URL
   ```

4. **Use proxy for caching**
   ```bash
   scurl --proxy http://caching-proxy.local:3128 URL
   ```

## Security Considerations

### ✅ Safe
- Using `--proxy` with trusted corporate proxy
- Setting reasonable `--timeout` values
- Custom `--header` for authentication
- `--retries` for reliability

### ⚠️ Use with Caution
- `--insecure` (disables SSL verification)
- Proxy with embedded credentials (use env vars instead)
- Very long timeouts (can hang builds)
- Too many retries (can slow down failures)

### ❌ Never Do
- `--insecure` in production
- Proxy credentials in CI logs
- Disable redirects without understanding impact
- Zero timeout (will always fail)

## Examples by Use Case

### Download from GitHub Behind Proxy
```bash
scurl --proxy http://proxy.company.com:8080 \
  https://raw.githubusercontent.com/org/repo/main/install.sh
```

### Private API Requiring Token
```bash
scurl -H "Authorization: Bearer $API_TOKEN" \
  https://api.company.com/scripts/deploy.sh
```

### Slow Server with Retries
```bash
scurl --timeout 120 --retries 10 \
  https://slow-server.example.com/script.sh
```

### Internal Server with Self-Signed Cert
```bash
scurl --insecure \
  https://internal-server.corp/install.sh
```

### Maximum Compatibility
```bash
scurl \
  --timeout 300 \
  --retries 10 \
  --max-redirects 50 \
  --system-proxy \
  URL
```

