# tests/test_nscan.py

import unittest
import os
import sys
from unittest.mock import patch, MagicMock

# --- Adjust import path as needed ---
# If nscan.py is in the parent directory or PYTHONPATH is set,
# you might do:
# sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from nscan import (
        create_session,
        test_nextjs_middleware_bypass,
        check_nextjs,  # If your script has this function
        DEFAULT_USER_AGENT,
        colorize_output,
        RequestResult # Import the NamedTuple used by send_request
    )
    from requests.exceptions import ConnectionError  # Import needed for retry tests

    # If colorama is installed, check for advanced color tests:
    try:
        import colorama
        COLORAMA_INSTALLED = True
    except ImportError:
        COLORAMA_INSTALLED = False

except ImportError as e:
    print(f"Error importing test target: {e}")
    print("Please ensure 'nscan.py' is accessible (e.g., in PYTHONPATH or parent dir).")
    sys.exit(1)
# --- End Import Path Adjustment ---


class TestNscan(unittest.TestCase):
    """
    Advanced unittest scenarios covering multiple behaviors of the
    nscan middleware bypass testing script.
    """

    @patch("nscan.requests.Session.request")
    def test_bypass_detected(self, mock_request):
        """
        Scenario: Normal=403, Crafted=200 -> Expect Bypass Verdict
        """
        mock_request.side_effect = [
            MagicMock(status_code=403, text="Forbidden", headers={}),
            MagicMock(status_code=200, text="OK", headers={}),
        ]

        with create_session() as session:
            result = test_nextjs_middleware_bypass(
                session=session, target_url="https://example.com", protected_path="/admin",
                timeout=5, user_agent=DEFAULT_USER_AGENT, method="GET", json_output=False,
                verbose=False, allow_redirects_crafted=False, extra_sensitive_headers=None,
                snippet_length=300
            )
        self.assertIn("Potential middleware bypass detected", result)
        self.assertEqual(mock_request.call_count, 2)
        self.assertEqual(mock_request.call_args_list[0].kwargs["method"], "GET")
        self.assertEqual(mock_request.call_args_list[1].kwargs["method"], "GET")


    @patch("nscan.requests.Session.request")
    def test_no_bypass_detected_verbose(self, mock_request):
        """
        Scenario: Normal=200, Crafted=200 -> Expect No Bypass Verdict + Verbose Output
        """
        mock_request.side_effect = [
            MagicMock(status_code=200, text="Home Page Content", headers={"Content-Type": "text/html"}),
            MagicMock(status_code=200, text="Home Page Content Again", headers={"Content-Type": "text/html"}),
        ]

        with create_session() as session:
            result = test_nextjs_middleware_bypass(
                session=session, target_url="https://example.com", protected_path="/home",
                timeout=5, user_agent=DEFAULT_USER_AGENT, method="GET", json_output=False,
                verbose=True, allow_redirects_crafted=False, extra_sensitive_headers=None,
                snippet_length=10  # intentionally short snippet
            )

        self.assertIn("No obvious middleware bypass", result)
        self.assertIn("(Both returned 200)", result)
        self.assertIn("--- Normal Response Snippet ---", result)
        self.assertIn("Home Page ", result)  # partial snippet
        self.assertNotIn("Content", result.split("--- Normal Response Snippet ---")[1])  # confirm truncation
        self.assertIn("--- Crafted Response Snippet ---", result)


    @patch("nscan.requests.Session.request")
    def test_responses_differ_redirect(self, mock_request):
        """
        Scenario: Normal=200, Crafted=302 -> Expect Differ Verdict
        """
        mock_request.side_effect = [
            MagicMock(status_code=200, text="OK", headers={}),
            MagicMock(status_code=302, text="Redirecting...", headers={"Location": "/login"}),
        ]

        with create_session() as session:
            result = test_nextjs_middleware_bypass(
                session=session, target_url="https://example.com", protected_path="/resource",
                timeout=5, user_agent=DEFAULT_USER_AGENT, method="GET", json_output=False,
                verbose=False, allow_redirects_crafted=False, extra_sensitive_headers=None,
            )
        self.assertIn("Responses differ (Normal: 200 vs Crafted: 302)", result)


    @patch("nscan.requests.Session.request")
    def test_server_errors(self, mock_request):
        """
        Scenario: Normal=200, Crafted=500 -> Expect Server Error Verdict
        """
        mock_request.side_effect = [
            MagicMock(status_code=200, text="OK", headers={}),
            MagicMock(status_code=500, text="Internal Server Error", headers={}),
        ]

        with create_session() as session:
            result = test_nextjs_middleware_bypass(
                session=session, target_url="https://example.com", protected_path="/api/data",
                timeout=5, user_agent=DEFAULT_USER_AGENT, method="GET", json_output=False,
                verbose=False, allow_redirects_crafted=False
            )
        self.assertIn("Unusual server error(s)", result)
        self.assertIn("(Normal: 200, Crafted: 500)", result)


    @patch("nscan.requests.Session.request")  # still patch even if none should be called
    def test_invalid_url(self, mock_request):
        """
        Scenario: Invalid URL -> Expect an error before any request is made
        """
        with create_session() as session:
            result = test_nextjs_middleware_bypass(
                session=session, target_url="htp://invalid-scheme", protected_path="/admin",
                timeout=5, user_agent=DEFAULT_USER_AGENT,
            )
        mock_request.assert_not_called()
        self.assertIn("Invalid target URL format", result)


    @patch("nscan.requests.Session.request")
    def test_method_post(self, mock_request):
        """
        Scenario: Using POST method -> Expect No Bypass if both return 401
        """
        mock_request.side_effect = [
            MagicMock(status_code=401, text="Unauthorized POST", headers={}),
            MagicMock(status_code=401, text="Unauthorized POST again", headers={}),
        ]

        with create_session() as session:
            result = test_nextjs_middleware_bypass(
                session=session, target_url="https://example.com", protected_path="/api/action",
                timeout=5, user_agent=DEFAULT_USER_AGENT, method="POST", verbose=False
            )
        self.assertIn("No obvious middleware bypass", result)
        self.assertIn("(Both returned 401)", result)
        self.assertEqual(mock_request.call_count, 2)
        self.assertEqual(mock_request.call_args_list[0].kwargs["method"], "POST")
        self.assertEqual(mock_request.call_args_list[1].kwargs["method"], "POST")


    @patch("nscan.requests.Session.request")
    def test_json_output_bypass(self, mock_request):
        """
        Scenario: Bypass detected (403->200) with JSON output -> Expect Dict result
        """
        mock_request.side_effect = [
            MagicMock(status_code=403, text="Forbidden", headers={}),
            MagicMock(status_code=200, text="Success Data", headers={}),
        ]

        with create_session() as session:
            result = test_nextjs_middleware_bypass(
                session=session, target_url="https://example.com", protected_path="/api/private",
                timeout=5, user_agent=DEFAULT_USER_AGENT, method="GET", json_output=True
            )
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("normal_status"), 403)
        self.assertEqual(result.get("crafted_status"), 200)
        self.assertEqual(
            result.get("verdict"),
            "Potential middleware bypass detected (Access Denied -> OK)!"
        )


    @patch("nscan.requests.Session.head")
    def test_check_nextjs_detected(self, mock_head):
        """
        Scenario: HEAD response has Next.js headers -> Expect check_nextjs logs info
        """
        mock_head.return_value = MagicMock(
            status_code=200,
            headers={"X-Powered-By": "Next.js", "Server": "Vercel"}
        )

        with create_session() as session:
            # Assuming check_nextjs exists in nscan.py
            check_nextjs(session, "https://is-nextjs.com")

        mock_head.assert_called_once_with("https://is-nextjs.com/", timeout=5, allow_redirects=True)


    @unittest.skipUnless(COLORAMA_INSTALLED, "colorama not installed")
    def test_colorize_output_bypass(self):
        """Scenario: Text indicates bypass -> Expect GREEN color code"""
        import colorama
        sample_text = "Verdict: Potential middleware bypass detected (Access Denied -> OK)!"
        colored_text = colorize_output(sample_text)
        self.assertIn(colorama.Fore.GREEN, colored_text)


    @unittest.skipUnless(COLORAMA_INSTALLED, "colorama not installed")
    def test_colorize_output_error(self):
        """Scenario: Text indicates ERROR -> Expect RED color code"""
        import colorama
        sample_text = "[ERROR] Connection error: timed out"
        colored_text = colorize_output(sample_text)
        self.assertIn(colorama.Fore.RED + "[ERROR]", colored_text)


    @unittest.skipUnless(COLORAMA_INSTALLED, "colorama not installed")
    def test_colorize_output_no_bypass(self):
        """Scenario: 'No obvious middleware bypass' -> Expect CYAN color code"""
        import colorama
        sample_text = "Verdict: No obvious middleware bypass (Both returned 200)."
        colored_text = colorize_output(sample_text)
        self.assertIn(colorama.Fore.CYAN + "Verdict: No obvious", colored_text)


    # --- Advanced Tests ---

    @patch("nscan.requests.Session.request")
    def test_no_bypass_various_statuses_with_subtest(self, mock_request):
        """Scenario: Test multiple "no bypass" pairs using subTest: (200,200), (404,404)"""
        status_pairs = [(200, 200), (404, 404)]
        for (normal_code, crafted_code) in status_pairs:
            with self.subTest(normal=normal_code, crafted=crafted_code):
                mock_request.side_effect = [
                    MagicMock(status_code=normal_code, text="Normal"),
                    MagicMock(status_code=crafted_code, text="Crafted"),
                ]
                mock_request.reset_mock() # Reset mock between subtests

                with create_session() as session:
                    result = test_nextjs_middleware_bypass(
                        session=session, target_url="https://example.com", protected_path="/test",
                        timeout=5, user_agent=DEFAULT_USER_AGENT, method="GET",
                    )
                self.assertIn("No obvious middleware bypass", result)
                self.assertIn(f"(Both returned {normal_code})", result)
                self.assertEqual(mock_request.call_count, 2)


    @patch("nscan.requests.Session.request")
    def test_logging_output_capture(self, mock_request):
        """Scenario: Check specific log messages appear using assertLogs."""
        mock_request.side_effect = [ MagicMock(status_code=401), MagicMock(status_code=401) ]

        with self.assertLogs(level="INFO") as log_capture:
            with create_session() as session:
                _ = test_nextjs_middleware_bypass(
                       session=session, target_url="https://example.com", protected_path="/api",
                       timeout=5, user_agent=DEFAULT_USER_AGENT
                   )

        logs_joined = "\n".join(log_capture.output)
        self.assertIn("Sending normal request...", logs_joined)
        self.assertIn("Sending crafted request with x-middleware-subrequest...", logs_joined)
        self.assertIn("Verdict: No obvious middleware bypass", logs_joined)
        self.assertNotIn("Final URL to test:", logs_joined) # Check DEBUG message absence


    # ***** MODIFIED RETRY TESTS *****
    # Patching the higher-level send_request function for these specific tests

    @patch("nscan.send_request") # Target the helper function
    def test_retry_behavior_success(self, mock_send_request):
        """
        Scenario: Simulate send_request succeeding after internal retries for normal call.
        Expect: Final verdict is "No bypass", send_request called twice total.
        """
        # Simulate: Normal request *finally* returns 200 after retries inside send_request
        # Simulate: Crafted request returns 200
        mock_send_request.side_effect = [
            RequestResult(MagicMock(status_code=200, text="Recovered", headers={}), 0.2, None), # Final result of Normal call
            RequestResult(MagicMock(status_code=200, text="Crafted OK", headers={}), 0.1, None)   # Final result of Crafted call
        ]

        # Session object still needed, but its retry config doesn't matter for this mock
        with create_session() as session:
            result = test_nextjs_middleware_bypass(
                session=session, target_url="https://example.com", protected_path="/retry",
                timeout=5, user_agent=DEFAULT_USER_AGENT
            )

        # Expect "No bypass" because both final results are 200
        self.assertIn("No obvious middleware bypass (Both returned 200).", result)
        # send_request is now called only ONCE for normal, ONCE for crafted
        self.assertEqual(mock_send_request.call_count, 2)


    @patch("nscan.send_request") # Target the helper function
    def test_retry_exhausted_failure(self, mock_send_request):
        """
        Scenario: Simulate send_request failing after exhausting internal retries for normal call.
        Expect: Error reported for normal request, send_request called once total.
        """
        # Simulate: Normal request *finally* returns an error after retries inside send_request
        final_error_msg = "Connection error: Simulated fail 2"
        mock_send_request.return_value = RequestResult(None, 0.3, final_error_msg)

        with create_session() as session: # Session retry config irrelevant here
            result = test_nextjs_middleware_bypass(
                session=session, target_url="https://example.com", protected_path="/fail",
                timeout=5, user_agent=DEFAULT_USER_AGENT
            )

        # The script should report the final error from send_request
        self.assertIn(f"[ERROR] Normal Request: {final_error_msg}", result)
        # send_request is only called ONCE for the normal request; it fails, so crafted isn't called
        self.assertEqual(mock_send_request.call_count, 1)


if __name__ == "__main__":
    unittest.main()