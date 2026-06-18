# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_httpx
# Purpose:      SpiderFoot plug-in for using the httpx tool.
#               Tool: https://github.com/projectdiscovery/httpx
#
# Author:       Trent Tanchin <trent@tanchin.org>
#
# Created:      2024-06-11
# Copyright:    (c) Trent Tanchin 2024
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import os
import sys
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootPlugin, SpiderFootEvent, SpiderFootHelpers


class sfp_tool_httpx(SpiderFootPlugin):

    meta = {
        "name": "Tool - httpx",
        "summary": "Fast and multi-purpose HTTP toolkit that probes websites and returns response information.",
        "flags": ["tool"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "name": "httpx",
            "description": "httpx is a fast and multi-purpose HTTP toolkit that allows you to run multiple proctors "
                           "using the retryablehttp-go library, ease the process of probing HTTP servers using the "
                           "same input url, and gain perspective on the world. It can detect web servers, "
                           "technologies, and other interesting information from the HTTP response.",
            "website": "https://httpx.projectdiscovery.io/",
            "repository": "https://github.com/projectdiscovery/httpx"
        }
    }

    # Default options
    opts = {
        "httpx_path": "",
        "httpx_follow_redirects": False,
        "httpx_timeout": 10,
        "httpx_concurrency": 50
    }

    # Option descriptions
    optdescs = {
        "httpx_path": "Path to your httpx binary. Must be set.",
        "httpx_follow_redirects": "Enable following redirects?",
        "httpx_timeout": "Seconds to wait before timing out the request.",
        "httpx_concurrency": "Maximum number of probes to run simultaneously."
    }

    # Target
    results = None
    errorState = False

    def setup(self, sfc, userOpts=None):
        if userOpts is None:
            userOpts = dict()
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["INTERNET_NAME"]

    def producedEvents(self):
        return [
            "TCP_PORT_OPEN",
            "LINKED_URL_INTERNAL",
            "WEBSERVER_HTTPHEADERS",
            "WEBSERVER_TECHNOLOGY",
            "WEBSERVER_BANNER",
            "SSL_CERTIFICATE_ISSUED",
            "SSL_CERTIFICATE_ISSUER",
            "SSL_CERTIFICATE_EXPIRED",
            "SSL_CERTIFICATE_EXPIRING",
            "SSL_CERTIFICATE_MISMATCH",
            "IP_ADDRESS",
            "SOFTWARE_USED",
            "TARGET_WEB_CONTENT_TYPE"
        ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if srcModuleName == self.__name__:
            return

        if not self.opts['httpx_path']:
            self.error("You enabled sfp_tool_httpx but did not set a path to the tool!")
            self.errorState = True
            return

        exe = self.opts["httpx_path"]
        if self.opts["httpx_path"].endswith("/"):
            exe = f"{exe}httpx"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        # Validate that the binary is the Go httpx tool (projectdiscovery)
        # and not the Python httpx library, which has incompatible CLI options.
        if not hasattr(self, "_httpxValidated"):
            self._httpxValidated = True
            try:
                p = Popen([exe, "-json", "-silent", "https://example.com"],
                          stdout=PIPE, stderr=PIPE)
                _, stderr = p.communicate(timeout=15)
                stderr_text = stderr.decode(sys.stderr.encoding, errors="replace")
                # Python httpx: -json expects a value, -silent is not a valid flag
                # → exits with code 2 and prints "No such option"
                if p.returncode != 0 and ("No such option" in stderr_text
                                          or "invalid value" in stderr_text.lower()
                                          or "invalid choice" in stderr_text.lower()):
                    self.error(
                        "httpx binary does not recognize -json / -silent flags. "
                        "This appears to be the Python httpx library (pip install httpx), "
                        "not the Go httpx tool from projectdiscovery. "
                        "Install the Go tool: https://github.com/projectdiscovery/httpx"
                    )
                    self.errorState = True
                    return
            except OSError:
                # Exit non-zero is expected for unreachable hosts — that's fine.
                # If we get an exception here (e.g. the binary is not executable),
                # that's also fine; we'll catch it on the real run.
                pass

        if not SpiderFootHelpers.sanitiseInput(eventData):
            self.debug("Invalid input, skipping.")
            return

        # Don't process the same URL twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already scanned.")
            return

        self.results[eventData] = True

        # Build the httpx command
        args = [
            exe,
            "-json",
            "-silent",
            "-timeout", str(self.opts["httpx_timeout"]),
            "-concurrency", str(self.opts["httpx_concurrency"]),
        ]

        if self.opts.get("httpx_follow_redirects", False):
            args.append("-follow-redirects")

        # Ensure the target has a scheme
        url = eventData
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{eventData}"

        args.append(url)

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            try:
                stdout, stderr = p.communicate(input=None, timeout=int(self.opts["httpx_timeout"]) + 10)
                if p.returncode == 0:
                    content = stdout.decode(sys.stdout.encoding)
                else:
                    self.debug(f"httpx returned non-zero exit code for {eventData}")
                    return
            except TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                self.debug(f"Timed out waiting for httpx to finish on {eventData}")
                return
        except OSError as e:
            self.error(f"Unable to run httpx: {e}")
            return

        if not content:
            self.debug(f"httpx returned no output for {eventData}")
            return

        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError) as e:
            self.error(f"Could not parse httpx output as JSON: {e}")
            self.debug(f"httpx output: {content}")
            return

        if not isinstance(data, dict):
            self.debug(f"httpx returned unexpected output format for {eventData}")
            return

        self._processResult(data, event, eventData)

    def _processResult(self, data, event, originalEvent) -> None:
        """Process a single httpx JSON result and emit SpiderFoot events.

        Args:
            data: Parsed JSON object from httpx output.
            event: Original SpiderFoot event.
            originalEvent: Original event data string.
        """
        url = data.get("url", "")
        if not url:
            url = data.get("matched-at", "")
        if not url:
            return

        host = data.get("host", originalEvent)
        port = data.get("port", "")
        title = data.get("title", "")
        content_type = data.get("content_type", "")
        server = data.get("server", "")
        tech_list = data.get("tech", [])
        headers = data.get("headers", {})
        response_headers = data.get("response_headers", headers)
        ip_addresses = data.get("a", [])
        cname_list = data.get("cname", [])
        tls_version = data.get("tls_version", "")
        tls_cert_subject = data.get("tls_cert_subject", "")
        tls_cert_issuer = data.get("tls_cert_issuer", "")
        tls_cert_san = data.get("tls_cert_san", [])
        tls_cert_expires = data.get("tls_cert_expires_at", "")
        tls_failed = data.get("tls_failed", False)
        error = data.get("error", "")

        # Determine the base event for this host
        base_event = event

        # Emit IP addresses from DNS resolution
        for ip in ip_addresses:
            if self.sf.validIP(ip):
                ip_evt = SpiderFootEvent(
                    "IP_ADDRESS", ip, self.__name__, base_event
                )
                self.notifyListeners(ip_evt)

        # Emit CNAMEs as additional internet names
        for cname in cname_list:
            if cname and cname != host:
                cname_evt = SpiderFootEvent(
                    "INTERNET_NAME", cname, self.__name__, base_event
                )
                self.notifyListeners(cname_evt)

        # Emit open TCP port if we know the port
        if port:
            port_evt = SpiderFootEvent(
                "TCP_PORT_OPEN", f"{host}:{port}", self.__name__, base_event
            )
            self.notifyListeners(port_evt)

        # Emit URL
        url_data = url
        if title:
            url_data += f" [title: {title}]"
        url_evt = SpiderFootEvent(
            "LINKED_URL_INTERNAL", url_data, self.__name__, base_event
        )
        self.notifyListeners(url_evt)

        # Emit HTTP headers
        if response_headers:
            header_text = "\n".join(f"{k}: {v}" for k, v in response_headers.items())
            header_evt = SpiderFootEvent(
                "WEBSERVER_HTTPHEADERS", header_text, self.__name__, base_event
            )
            self.notifyListeners(header_evt)

        # Emit web server banner
        if server:
            banner_evt = SpiderFootEvent(
                "WEBSERVER_BANNER", server, self.__name__, base_event
            )
            self.notifyListeners(banner_evt)

        # Emit technologies
        for tech in tech_list:
            if isinstance(tech, dict):
                tech_name = tech.get("name", tech.get("docker", ""))
            else:
                tech_name = str(tech)

            if not tech_name:
                continue

            # Classify into SOFTWARE_USED or WEBSERVER_TECHNOLOGY
            evt_type = "WEBSERVER_TECHNOLOGY"
            evt = SpiderFootEvent(
                evt_type, tech_name, self.__name__, base_event
            )
            self.notifyListeners(evt)

        # Emit content type
        if content_type:
            ct_evt = SpiderFootEvent(
                "TARGET_WEB_CONTENT_TYPE", content_type, self.__name__, base_event
            )
            self.notifyListeners(ct_evt)

        # Emit SSL/TLS certificate information
        if tls_failed is False and (tls_cert_subject or tls_version):
            # Emit certificate subject (issued to)
            if tls_cert_subject:
                cert_evt = SpiderFootEvent(
                    "SSL_CERTIFICATE_ISSUED", tls_cert_subject, self.__name__, base_event
                )
                self.notifyListeners(cert_evt)

            # Emit certificate issuer
            if tls_cert_issuer:
                issuer_evt = SpiderFootEvent(
                    "SSL_CERTIFICATE_ISSUER", tls_cert_issuer, self.__name__, base_event
                )
                self.notifyListeners(issuer_evt)

            # Emit certificate expiration
            if tls_cert_expires:
                try:
                    from datetime import datetime
                    # httpx outputs ISO 8601 format
                    exp_str = tls_cert_expires.replace("Z", "+00:00")
                    exp_dt = datetime.fromisoformat(exp_str)
                    now = datetime.now(exp_dt.tzinfo)

                    if exp_dt < now:
                        exp_evt = SpiderFootEvent(
                            "SSL_CERTIFICATE_EXPIRED",
                            f"Certificate for {host} expired on {tls_cert_expires}",
                            self.__name__, base_event
                        )
                        self.notifyListeners(exp_evt)
                    else:
                        # Check if expiring within 30 days
                        from datetime import timedelta
                        if (exp_dt - now) < timedelta(days=30):
                            exp_evt = SpiderFootEvent(
                                "SSL_CERTIFICATE_EXPIRING",
                                f"Certificate for {host} expires on {tls_cert_expires}",
                                self.__name__, base_event
                            )
                            self.notifyListeners(exp_evt)
                except (ValueError, TypeError) as e:
                    self.debug(f"Could not parse certificate expiration date: {tls_cert_expires} ({e})")

            # Emit hostname mismatch if host doesn't match SAN or subject
            if tls_cert_san:
                san_list = tls_cert_san if isinstance(tls_cert_san, list) else [tls_cert_san]
                matched = False
                for san in san_list:
                    if self._hostMatches(san, host):
                        matched = True
                        break
                if not matched and host not in san_list:
                    mismatch_evt = SpiderFootEvent(
                        "SSL_CERTIFICATE_MISMATCH",
                        f"Certificate for {host} does not match SAN: {', '.join(san_list)}",
                        self.__name__, base_event
                    )
                    self.notifyListeners(mismatch_evt)

        # Handle errors reported by httpx
        if error:
            self.debug(f"httpx reported error for {host}: {error}")

    def _hostMatches(self, san, host) -> bool:
        """Check if a hostname matches an SSL SAN entry.

        Args:
            san: SAN entry from certificate.
            host: Hostname to check.

        Returns:
            True if hostname matches the SAN entry.
        """
        if not san or not host:
            return False
        san_lower = san.lower().strip(".")
        host_lower = host.lower().strip(".")
        if san_lower == host_lower:
            return True
        # Wildcard match: *.example.com matches foo.example.com but not example.com
        if san_lower.startswith("*."):
            base = san_lower[2:]
            parts = host_lower.split(".", 1)
            if len(parts) == 2 and parts[1] == base:
                return True
        return False


# End of sfp_tool_httpx class
