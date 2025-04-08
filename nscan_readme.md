# NSCAN - Next.js Middleware Bypass Scanner

> **Disclaimer**: These scripts and tools are intended **strictly** for **educational purposes** and **authorized security testing** only. See the full disclaimer below.

---

## Table of Contents

- [Important Disclaimer](#important-disclaimer)
- [About This Repository](#about-this-repository)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Available Scripts](#available-scripts)
  - [nscan.py - Next.js Middleware Bypass Tester](#nscanpy---nextjs-middleware-bypass-tester)
    - [Basic Usage](#basic-usage)
    - [Advanced Usage & Options](#advanced-usage--options)
    - [Configuration File Example](#configuration-file-example)
    - [Example Output](#example-output)
- [Understanding Results](#understanding-results)
- [Use Cases](#use-cases)
- [Testing the Scripts](#testing-the-scripts)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Contributing](#contributing)
- [References](#references)

---

## Important Disclaimer

**These scripts are provided for educational and authorized testing only.**  
- **DO NOT** run these tools against any system or application without **explicit written permission**.  
- Unauthorized security testing or exploitation can be **illegal**, **unethical**, and carries potential legal consequences.  
- The repository's author(s) assume **no liability** for misuse or damage caused by these tools.  
- Always obtain permission and comply with all relevant laws and guidelines before scanning.

**Use responsibly, legally, and ethically.**

---

## About This Repository

This repository contains Python scripts focused on web security research and **authorized** vulnerability assessments. The main script currently targets **Next.js middleware bypass** scenarios. Over time, more scripts for various vulnerabilities or scanning patterns may be added.

**Status**: The primary tool here is `nscan.py` for testing potential Next.js vulnerabilities (especially via the `x-middleware-subrequest` header trick). Future scripts will appear as development progresses.

---

## Getting Started

### Prerequisites

- **Python 3.7+**  
  Make sure you have Python 3.7 or higher installed.  
- **Git**  
  Required for cloning the repo (or you can download the ZIP).
- **Required packages**:
  - requests
  - colorama (optional, for colored output)

### Installation

1. **Clone the Repository**:

    ```bash
    git clone https://github.com/surreal-utopia/cve.git
    cd cve
    ```

2. **Install Dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

---

## Available Scripts

### `nscan.py` - Next.js Middleware Bypass Tester

This script checks for potential middleware bypass vulnerabilities in Next.js by sending a **normal** request vs. a **crafted** request that includes the `x-middleware-subrequest` header. If the normal request is blocked (e.g., `403`) and the crafted one succeeds (`200`), it may indicate a **possible bypass**.

#### Basic Usage

```bash
python nscan.py https://example.com /admin
```

This sends two GET requests and compares their responses. If it suspects a bypass, it will print a corresponding message.

#### Advanced Usage & Options

To see all options:

```bash
python nscan.py --help
```

##### Command Line Options

| Flag/Option | Description |
|-------------|-------------|
| `url` | Base URL to test (e.g., https://example.com) |
| `path` | Protected path to test (e.g., /admin) |
| `--url-file FILE` | Test multiple base URLs from a file (one per line). The `path` applies to all if provided. |
| `--method METHOD` | HTTP method (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH). Default is GET. |
| `--timeout FLOAT` | Overall request timeout (default: 10s). |
| `--connect-timeout FLOAT` | Separate connection timeout (overrides --timeout). |
| `--read-timeout FLOAT` | Separate read timeout (overrides --timeout). |
| `--user-agent STRING` | Customize the User-Agent header. |
| `--auth-header 'H: V'` | Add custom header(s), e.g. "Authorization: Bearer token". Repeatable. |
| `--follow-redirects-crafted` | Let the crafted request follow redirects (default: off). |
| `--disable-ssl-verify` | Disable SSL checks (INSECURE). |
| `--json, -j` | Output results in JSON. |
| `--output, -o FILE` | Save final output to a file. |
| `--verbose, -v` | Show response snippets (sanitized headers/body). |
| `--snippet-length INT` | Truncate the verbose snippet to N characters (default 300). |
| `--color` | Enable colored output if colorama is installed and stdout is a TTY. |
| `--debug-logs` | Enable extra debugging logs (including HTTP statuses, etc.). |
| `--config, -c FILE` | Load additional settings from a JSON file (see example below). |
| `--check-nextjs` | Perform a quick HEAD request to see if Next.js-related headers appear before scanning. |

##### Example:

```bash
python nscan.py \
  --url-file targets.txt \
  /api/action \
  --method POST \
  --connect-timeout 5 \
  --read-timeout 10 \
  --auth-header "Authorization: Bearer ABC123" \
  -c myconfig.json \
  -j \
  -o results.json \
  --verbose \
  --color
```

#### Configuration File Example

Create `config.json` like:

```json
{
  "user_agent": "CustomUserAgent/1.0",
  "timeout": 15.0,
  "retry_config": {
    "total": 3,
    "backoff_factor": 0.3,
    "status_forcelist": [500, 502, 503, 504]
  },
  "extra_sensitive_headers": ["x-api-key", "x-custom-auth"]
}
```

Then run:

```bash
python nscan.py https://example.com /admin --config config.json
```

#### Example Output

When a potential bypass is detected:

```
Target: https://example.com/admin
Normal Status: 403 (Method: GET, Redirects: True, Time: 0.34s)
Crafted Status: 200 (Method: GET, Redirects: False, Time: 0.28s)
Verdict: Potential middleware bypass detected (Access Denied -> OK)!

--- Normal Response Snippet ---
<html><body><h1>403 Forbidden</h1>You don't have permission to access this resource.</body></html>

--- Crafted Response Snippet ---
<!DOCTYPE html><html><head><title>Admin Dashboard</title></head>...
```

## Understanding Results

The tool compares responses from normal and crafted requests and reports a verdict:

- **Potential middleware bypass detected**: When normal request returns 401/403 but crafted request returns 200
- **No obvious middleware bypass**: When both requests return the same status code
- **Responses differ**: When requests return different status codes but not in a way that clearly indicates bypass
- **Unusual server error(s)**: When either request results in a 5xx error

## Use Cases

### Testing a Single Endpoint

```bash
python nscan.py https://example.com /admin --verbose
```

### Batch Testing Multiple Targets

Create a file `targets.txt` with URLs:
```
https://example.com
https://example-dev.com
https://staging.example.com
```

Then run:
```bash
python nscan.py --url-file targets.txt /admin --output results.txt
```

### Testing Authenticated Endpoints

```bash
python nscan.py https://example.com /api/users --auth-header "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --auth-header "x-api-key: your-api-key"
```

### Testing with Different HTTP Methods

```bash
python nscan.py https://example.com /api/users --method POST
```

## Testing the Scripts

This repository includes a `tests` folder containing unit tests (e.g., `test_nscan.py`). To run them:

```bash
# From the repo root:
python -m unittest discover tests
```

Or a specific file:

```bash
python -m unittest tests/test_nscan.py
```

These tests use mock responses to verify script logic and verdict output.

## Troubleshooting

- **SSL Verification Issues**: If you see SSL certificate errors, you can use `--disable-ssl-verify` (INSECURE) or provide a proper CA bundle.

- **Timeout / Connection Errors**: Adjust `--connect-timeout` and `--read-timeout` or check your network connectivity.

- **Missing Modules**: Ensure you ran `pip install -r requirements.txt`. If colorama is missing, colored output will be disabled.

- **Authorization**: If you need auth tokens or special headers, pass them via `--auth-header "Header: Value"` or a config file's `extra_sensitive_headers` to sanitize logs properly.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Feel free to open Pull Requests or Issues if you have improvements or find bugs. Make sure any new scripts or changes align with the repository's focus on ethical and authorized usage.

## References

- [Next.js Middleware Documentation](https://nextjs.org/docs/advanced-features/middleware)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
