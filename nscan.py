#!/usr/bin/env python3

"""
Next.js Middleware Bypass Tester

Basic Usage (non-technical users):
  python nextjs_bypass_test.py https://example.com /admin

Advanced Usage:
  - Use '--help' to see all optional flags for configuration,
    snippet length, batch testing, color output, HTTP method, etc.

Example:
  python nextjs_bypass_test.py https://example.com /admin --disable-ssl-verify --verbose
"""

import argparse
import json
import logging
import os
import sys
import time
from contextlib import contextmanager
from typing import Union, Dict, Any, Optional, Tuple, List, Set, Iterator, NamedTuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException, Timeout, ConnectionError
from urllib3.util.retry import Retry

# Try importing colorama for optional colored output
try:
    import colorama
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# Constants
DEFAULT_USER_AGENT: str = (
    "NextjsBypassTester/1.2 (Security Testing Script; +https://github.com/surreal-utopia/cve)"
    " Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
)

# Default retry settings
DEFAULT_RETRY_TOTAL: int = 3
DEFAULT_RETRY_BACKOFF: float = 0.3
DEFAULT_RETRY_STATUS_FORCELIST: List[int] = [500, 502, 503, 504]

# Default headers to sanitize in verbose output
DEFAULT_SENSITIVE_HEADERS: Set[str] = {"set-cookie", "cookie", "authorization"}

# Default environment variables
ENV_TIMEOUT = "TEST_TIMEOUT"
ENV_USER_AGENT = "TEST_USER_AGENT"
ENV_DEBUG = "TEST_DEBUG"
ENV_CONFIG_PATH = "TEST_CONFIG_PATH"


class RequestResult(NamedTuple):
    """
    Container for request results to improve type safety and readability.
    """
    response: Optional[requests.Response]
    duration: float
    error_message: Optional[str]


def setup_logging(debug_logs: bool = False) -> None:
    """
    Configure logging level (INFO by default, DEBUG if --debug-logs is used).
    """
    log_level = logging.DEBUG if debug_logs else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_config(config_path: Optional[str]) -> Dict[str, Any]:
    """Load optional overrides from a JSON config file."""
    if not config_path:
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        logging.info(f"Configuration loaded from: {config_path}")
        
        # Validate config structure
        _validate_config(config)
        return config
        
    except FileNotFoundError:
        logging.error(f"Config file not found at {config_path}. Using defaults.")
        return {}
    except json.JSONDecodeError as e:
        logging.error(f"JSON decode error for config {config_path}: {e}")
        return {}
    except Exception as e:
        logging.error(f"Unexpected error loading config: {e}", exc_info=True)
        return {}


def _validate_config(config: Dict[str, Any]) -> None:
    """Validate configuration parameters."""
    if "timeout" in config and (not isinstance(config["timeout"], int) or config["timeout"] <= 0):
        logging.warning("Invalid 'timeout' in config. Ignoring.")
        config.pop("timeout")
    
    if "user_agent" in config and not isinstance(config["user_agent"], str):
        logging.warning("Invalid 'user_agent' type. Ignoring.")
        config.pop("user_agent")
    
    if "retry_config" in config and not isinstance(config["retry_config"], dict):
        logging.warning("Invalid 'retry_config' structure. Ignoring.")
        config.pop("retry_config")
    
    if "extra_sensitive_headers" in config and (
        not isinstance(config["extra_sensitive_headers"], list) or
        not all(isinstance(h, str) for h in config["extra_sensitive_headers"])
    ):
        logging.warning("Invalid 'extra_sensitive_headers'. Ignoring.")
        config.pop("extra_sensitive_headers")


def validate_url(url: str) -> bool:
    """Return True if URL has a valid scheme (http/https) and a hostname."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ["http", "https"] and bool(parsed.netloc)
    except ValueError:
        return False


@contextmanager
def create_session(retry_config: Optional[Dict[str, Any]] = None,
                   disable_ssl_verify: bool = False) -> Iterator[requests.Session]:
    """
    Create a requests.Session with retry logic and SSL verification toggle.
    Using context manager for proper resource cleanup.
    """
    session = requests.Session()

    try:
        config = retry_config or {}
        total = config.get("total", DEFAULT_RETRY_TOTAL)
        backoff = config.get("backoff_factor", DEFAULT_RETRY_BACKOFF)
        statuses = config.get("status_forcelist", DEFAULT_RETRY_STATUS_FORCELIST)

        # Basic sanity checks; fall back to defaults if invalid
        if not (isinstance(total, int) and total >= 0):
            total = DEFAULT_RETRY_TOTAL
        if not (isinstance(backoff, (int, float)) and backoff >= 0):
            backoff = DEFAULT_RETRY_BACKOFF
        if not (isinstance(statuses, list) and all(isinstance(s, int) for s in statuses)):
            statuses = DEFAULT_RETRY_STATUS_FORCELIST

        logging.debug(f"Session retries: total={total}, backoff={backoff}, statuses={statuses}")
        logging.debug("Note: For detailed retry attempt logs, consider enabling urllib3's debug logs with "
                      "environment variables or a custom logging adapter.")

        retries = Retry(
            total=total,
            backoff_factor=backoff,
            status_forcelist=statuses,
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.verify = not disable_ssl_verify
        if disable_ssl_verify:
            logging.warning("SSL certificate verification is DISABLED. This is insecure.")
            # Suppress urllib3's insecure warning if we want cleaner logs
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass

        yield session
    finally:
        # Ensure the session is properly closed when done
        session.close()


def sanitize_headers(headers: Dict[str, str], extra_sensitive: Optional[Set[str]] = None) -> Dict[str, str]:
    """Hide sensitive headers (default + extras) before logging or printing."""
    effective_sensitive = DEFAULT_SENSITIVE_HEADERS.copy()
    if extra_sensitive:
        effective_sensitive.update(extra_sensitive)
    return {
        k: ("[REDACTED]" if k.lower() in effective_sensitive else v)
        for k, v in headers.items()
    }


def send_request(
    session: requests.Session,
    url: str,
    headers: Dict[str, str],
    timeout: int,
    allow_redirects: bool,
    method: str = "GET"
) -> RequestResult:
    """
    Send an HTTP request (method=GET by default), returning a RequestResult named tuple.
    """
    start = time.time()
    err_msg: Optional[str] = None
    resp: Optional[requests.Response] = None

    try:
        # We now support user-specified method
        logging.debug(f"Sending {method} request to {url}. allow_redirects={allow_redirects}")
        resp = session.request(
            method=method.upper(),
            url=url,
            headers=headers,
            timeout=timeout,
            allow_redirects=allow_redirects
        )
    except Timeout:
        err_msg = f"Timeout error after {timeout}s"
        logging.warning(f"{err_msg} for {url}")
    except ConnectionError as e:
        reason = getattr(e, 'reason', e)
        err_msg = f"Connection error: {reason}"
        logging.warning(f"{err_msg} for {url}")
    except RequestException as e:
        err_msg = f"Request error: {e}"
        logging.error(f"{err_msg} for {url}", exc_info=True)
    finally:
        duration = time.time() - start

    return RequestResult(resp, duration, err_msg)


def test_nextjs_middleware_bypass(
    session: requests.Session,
    target_url: str,
    protected_path: str,
    timeout: int,
    user_agent: str,
    method: str = "GET",
    json_output: bool = False,
    verbose: bool = False,
    allow_redirects_crafted: bool = False,
    extra_sensitive_headers: Optional[List[str]] = None,
    snippet_length: int = 300
) -> Union[str, Dict[str, Any]]:
    """
    Perform normal vs crafted requests and compare results.
    Returns a dictionary if json_output is True, otherwise a formatted string report.
    """
    if not validate_url(target_url):
        error_msg = f"Invalid target URL format: {target_url}"
        logging.error(error_msg)
        if json_output:
            return {"url": target_url, "error": error_msg}
        else:
            return f"[ERROR] {error_msg}"

    base = target_url.rstrip("/") + "/"
    final_url = urljoin(base, protected_path.lstrip("/"))
    logging.debug(f"Final URL to test: {final_url}")

    extra_keys = {h.lower() for h in extra_sensitive_headers} if extra_sensitive_headers else None

    result: Dict[str, Any] = {
        "url": final_url,
        "normal_status": None,
        "crafted_status": None,
        "normal_response_time": None,
        "crafted_response_time": None,
        "verdict": "",
        "details": {}
    }

    common_headers = {"User-Agent": user_agent}

    # --- Normal Request ---
    logging.info("Sending normal request...")
    allow_redirects_normal = True
    normal_result = send_request(
        session=session,
        url=final_url,
        headers=common_headers,
        timeout=timeout,
        allow_redirects=allow_redirects_normal,
        method=method  # Use the user-specified method here
    )
    result["normal_response_time"] = normal_result.duration

    if normal_result.error_message or not normal_result.response:
        error_msg = normal_result.error_message or "No response received"
        result["verdict"] = "Error during normal request"
        result["details"]["error"] = error_msg
        if json_output:
            return result
        else:
            return f"Target: {final_url}\n[ERROR] Normal Request: {error_msg}"

    normal_status = normal_result.response.status_code
    result["normal_status"] = normal_status
    logging.debug(f"Normal response: {normal_status} in {normal_result.duration:.2f}s")

    if verbose:
        result["details"]["normal_response"] = {
            "status_code": normal_status,
            "headers": sanitize_headers(dict(normal_result.response.headers), extra_keys),
            "body_snippet": normal_result.response.text[:snippet_length],
            "response_time": f"{normal_result.duration:.2f}s"
        }

    # --- Crafted Request ---
    logging.info("Sending crafted request with x-middleware-subrequest...")
    crafted_headers = {**common_headers, "x-middleware-subrequest": "1"}
    logging.debug(
        "Crafted Headers (sanitized if verbose): "
        + (str(sanitize_headers(crafted_headers, extra_keys)) if verbose else str(crafted_headers))
    )
    logging.debug(f"Following redirects (crafted): {allow_redirects_crafted}")

    crafted_result = send_request(
        session=session,
        url=final_url,
        headers=crafted_headers,
        timeout=timeout,
        allow_redirects=allow_redirects_crafted,
        method=method
    )
    result["crafted_response_time"] = crafted_result.duration

    if crafted_result.error_message or not crafted_result.response:
        error_msg = crafted_result.error_message or "No response received"
        result["verdict"] = "Error during crafted request"
        result["details"]["error"] = error_msg
        if json_output:
            return result
        else:
            normal_status_str = f"Normal Status: {normal_status}\n"
            return f"Target: {final_url}\n{normal_status_str}[ERROR] Crafted Request: {error_msg}"

    crafted_status = crafted_result.response.status_code
    result["crafted_status"] = crafted_status
    logging.debug(f"Crafted response: {crafted_status} in {crafted_result.duration:.2f}s")

    if verbose:
        result["details"]["crafted_response"] = {
            "status_code": crafted_status,
            "headers": sanitize_headers(dict(crafted_result.response.headers), extra_keys),
            "body_snippet": crafted_result.response.text[:snippet_length],
            "response_time": f"{crafted_result.duration:.2f}s"
        }

    # --- Decision Logic ---
    if normal_status in [401, 403] and crafted_status == 200:
        result["verdict"] = "Potential middleware bypass detected (Access Denied -> OK)!"
    elif normal_status == crafted_status:
        result["verdict"] = f"No obvious middleware bypass (Both returned {normal_status})."
    else:
        if normal_status >= 500 or crafted_status >= 500:
            result["verdict"] = (
                f"Unusual server error(s) (Normal: {normal_status}, Crafted: {crafted_status}). "
                "Review recommended."
            )
        else:
            result["verdict"] = (
                f"Responses differ (Normal: {normal_status} vs Crafted: {crafted_status}). "
                "Further review needed."
            )

    logging.info(f"Verdict: {result['verdict']}")

    # --- Return based on json_output flag ---
    if json_output:
        return result
    else:
        # Format the dictionary into a string report
        output_lines = [
            f"Target: {result['url']}",
            f"Normal Status: {result.get('normal_status', 'N/A')} "
            f"(Method: {method}, Redirects: {allow_redirects_normal}, "
            f"Time: {result.get('normal_response_time', 0):.2f}s)",
            f"Crafted Status: {result.get('crafted_status', 'N/A')} "
            f"(Method: {method}, Redirects: {allow_redirects_crafted}, "
            f"Time: {result.get('crafted_response_time', 0):.2f}s)",
            f"Verdict: {result['verdict']}"
        ]

        if verbose:
            if "normal_response" in result["details"]:
                output_lines.append("\n--- Normal Response Snippet ---")
                output_lines.append(result["details"]["normal_response"].get("body_snippet", "[No snippet]"))
            if "crafted_response" in result["details"]:
                output_lines.append("\n--- Crafted Response Snippet ---")
                output_lines.append(result["details"]["crafted_response"].get("body_snippet", "[No snippet]"))

        return "\n".join(output_lines)


def colorize_output(text: str) -> str:
    """
    Simple function to colorize certain lines if colorama is installed
    and stdout is a TTY. For advanced usage only.
    """
    lines = text.split("\n")
    colorized_lines = []
    for line in lines:
        upper_line = line.upper()
        if "ERROR" in upper_line:
            # Red for errors
            line = f"{colorama.Fore.RED}{line}{colorama.Style.RESET_ALL}"
        elif "bypass detected" in line.lower():
            # Green for bypass detection
            line = f"{colorama.Fore.GREEN}{line}{colorama.Style.RESET_ALL}"
        elif "no obvious middleware bypass" in line.lower():
            # Cyan for "no bypass"
            line = f"{colorama.Fore.CYAN}{line}{colorama.Style.RESET_ALL}"
        elif line.startswith("Verdict:") and "no obvious" not in line.lower():
            # If there's any suspicious verdict, color it yellow
            line = f"{colorama.Fore.YELLOW}{line}{colorama.Style.RESET_ALL}"

        colorized_lines.append(line)

    return "\n".join(colorized_lines)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Test for Next.js middleware bypass via x-middleware-subrequest.\n\n"
            "Basic usage (non-technical):\n"
            "  python3 nextjs_bypass_test.py https://example.com /admin\n\n"
            "Advanced usage: see optional flags below."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Basic arguments or an optional URL file
    parser.add_argument("url", nargs="?", help="Base URL (e.g. https://example.com).")
    parser.add_argument("path", nargs="?", help="Protected path (e.g. /admin).")
    parser.add_argument("--url-file", help="File containing multiple URLs (one per line). If used, 'url' arg is ignored.")

    # Optional arguments for config, output, etc.
    parser.add_argument("--config", "-c", metavar="FILE",
                        default=os.getenv(ENV_CONFIG_PATH),
                        help="JSON config file for overrides (e.g., user_agent, timeout).")
    parser.add_argument("--timeout", type=int,
                        default=int(os.getenv(ENV_TIMEOUT, "10")),
                        help="Request timeout in seconds.")
    parser.add_argument("--user-agent", 
                        default=os.getenv(ENV_USER_AGENT, DEFAULT_USER_AGENT),
                        help="Custom User-Agent string.")
    parser.add_argument("--method", default="GET",
                        help="HTTP method to use (default GET).")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output results in JSON format.")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Save output to specified file.")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show response snippets (sanitized).")
    parser.add_argument("--snippet-length", type=int, default=300,
                        help="Max number of characters for response snippets (advanced).")
    parser.add_argument("--debug-logs", action="store_true",
                        default=os.getenv(ENV_DEBUG, "").lower() in ("true", "1", "yes"),
                        help="Enable detailed DEBUG logs (advanced).")
    parser.add_argument("--follow-redirects-crafted", action="store_true",
                        help="Allow the crafted request to follow redirects (default: False).")
    parser.add_argument("--disable-ssl-verify", action="store_true",
                        help="Disable SSL verification (INSECURE).")
    parser.add_argument("--color", action="store_true",
                        help="Enable colorized output (if colorama is installed and stdout is TTY).")

    # Optional Next.js pre-flight check
    parser.add_argument("--check-nextjs", action="store_true",
                        help="Perform a HEAD request on the base URL to see if it appears to be Next.js.")

    return parser.parse_args()


def process_url_list(args: argparse.Namespace, config: Dict[str, Any]) -> List[Dict[str, str]]:
    """Process the URL list from args and return a structured list of targets."""
    url_list: List[str] = []
    
    if args.url_file:
        # Use URLs from file
        if not os.path.isfile(args.url_file):
            logging.error(f"URL file not found: {args.url_file}")
            sys.exit(1)
        
        with open(args.url_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        
        url_list = lines
        if not url_list:
            logging.error(f"No valid URLs found in {args.url_file}")
            sys.exit(1)
        
        # If path is not given, we assume it's part of each URL or user is just scanning base
        if not args.path:
            logging.info("No path specified. Each URL in file is tested as-is.")
    else:
        # Single URL from CLI
        if not args.url:
            print("No URL provided. Use <URL> or --url-file.")
            sys.exit(1)
        
        url_list = [args.url]
        if not args.path:
            print("No path provided. Basic usage: <URL> <PATH>\nIf your URL includes the path, disregard this message.")
            print("Proceeding but the path will be empty.\n")
            args.path = ""
    
    # Convert to structured format for easier processing
    return [{"url": url, "path": args.path or ""} for url in url_list]


def check_nextjs(session: requests.Session, url: str) -> None:
    """
    Optional pre-flight check: do a HEAD request on the base URL, see if any Next.js headers appear.
    """
    base = url.rstrip("/") + "/"
    try:
        head_resp = session.head(base, timeout=5, allow_redirects=True)
        # Look for typical Next.js headers or patterns
        # For example, some Next.js setups show "x-middleware-cache", "x-nextjs-page", etc.
        nextjs_headers = [k for k in head_resp.headers.keys() if "nextjs" in k.lower() or "middleware" in k.lower()]
        if nextjs_headers:
            logging.info(f"Pre-flight check: Detected Next.js-related header(s) {nextjs_headers} at {base}")
        else:
            logging.info("Pre-flight check: Did not detect obvious Next.js headers. (May still be Next.js.)")
    except Exception as e:
        logging.warning(f"Pre-flight HEAD request failed for {base}: {e}")


def main() -> None:
    """Main entry point for the script."""
    # If no arguments at all, print a quick usage then exit
    if len(sys.argv) == 1:
        print("Usage: python3 nextjs_bypass_test.py <URL> <PATH> [options]\n"
              "       or use --help for details.")
        sys.exit(1)
    
    args = parse_args()
    setup_logging(debug_logs=args.debug_logs)

    # If user wants color, initialize colorama once (if installed)
    if args.color and COLORAMA_AVAILABLE and sys.stdout.isatty():
        colorama.init()
        logging.debug("Colorama initialized for colored output.")
    elif args.color and not COLORAMA_AVAILABLE:
        logging.warning("Color requested but 'colorama' not installed. No color will be applied.")

    config = load_config(args.config)

    # Determine effective user agent
    user_agent = args.user_agent or config.get("user_agent", DEFAULT_USER_AGENT)

    # Determine effective timeout (config > CLI > env > default)
    cli_timeout = args.timeout
    config_timeout = config.get("timeout")
    if config_timeout and isinstance(config_timeout, int) and config_timeout > 0:
        effective_timeout = config_timeout
    else:
        effective_timeout = cli_timeout

    retry_config = config.get("retry_config", {})
    extra_sensitive = config.get("extra_sensitive_headers", [])

    # Process URL list from args
    targets = process_url_list(args, config)
    
    all_results = []
    
    # Use session context manager for proper cleanup
    with create_session(
        retry_config=retry_config,
        disable_ssl_verify=args.disable_ssl_verify
    ) as session:
        # Optional pre-flight Next.js check
        if args.check_nextjs and targets:
            # We only do a HEAD request on the first target's base URL for demonstration
            # (You could do it for each target if desired.)
            logging.info("Performing optional Next.js pre-flight check...")
            check_nextjs(session, targets[0]["url"])

        # Process each URL
        for target in targets:
            output_data = test_nextjs_middleware_bypass(
                session=session,
                target_url=target["url"],
                protected_path=target["path"],
                timeout=effective_timeout,
                user_agent=user_agent,
                method=args.method,
                json_output=args.json,
                verbose=args.verbose,
                allow_redirects_crafted=args.follow_redirects_crafted,
                extra_sensitive_headers=extra_sensitive,
                snippet_length=args.snippet_length
            )
            all_results.append(output_data)

    # If JSON, combine results
    if args.json:
        # Convert each item to dict if it's not already
        results_for_json: List[Dict[str, Any]] = []
        for item in all_results:
            if isinstance(item, dict):
                results_for_json.append(item)
            else:
                # This would typically be an error string or something
                results_for_json.append({"error": str(item)})
        final_output = json.dumps(results_for_json, indent=2)
    else:
        # Plain text: join each result with a blank line
        lines = []
        for res in all_results:
            if isinstance(res, dict):
                # Possibly an error or partial data in dict form
                error_detail = res.get("error") or res.get("details", {}).get("error")
                if error_detail:
                    text_block = f"Target: {res.get('url', 'Unknown')}\n[ERROR] {error_detail}"
                else:
                    # Or a normal result dict that didn't go JSON
                    text_block = str(res)
            else:
                text_block = res  # Already a string
            lines.append(text_block)

        final_output = "\n\n".join(lines)

        # If user requested color and conditions are right, colorize
        if args.color and COLORAMA_AVAILABLE and sys.stdout.isatty():
            final_output = colorize_output(final_output)

    print(final_output)

    # Save to file if requested
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(final_output)
            logging.info(f"Output saved to {args.output}")
            print(f"\nOutput also saved to: {args.output}")
        except IOError as e:
            logging.error(f"Error writing to file {args.output}: {e}", exc_info=True)
            print(f"\nError writing to file {args.output}: {e}")

    # If we initialized colorama, we can de-init now (optional).
    # If you want to keep it for other prints, you can remove this.
    if args.color and COLORAMA_AVAILABLE and sys.stdout.isatty():
        colorama.deinit()
        logging.debug("Colorama deinitialized.")


if __name__ == "__main__":
    main()
