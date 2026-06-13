# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_ffuf
# Purpose:      SpiderFoot plug-in for using the ffuf tool.
#               Tool: https://github.com/ffuf/ffuf
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


class sfp_tool_ffuf(SpiderFootPlugin):

    meta = {
        "name": "Tool - ffuf",
        "summary": "Fast web fuzzer written in Go. Brute-forces directories and files in "
                   "web sites, producing results that map to SpiderFoot URL and vulnerability events.",
        "flags": ["tool", "slow"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "name": "ffuf",
            "description": "ffuf (Fuzz Faster U Fool) is a fast web fuzzer written in Go. "
                           "It can fuzz any part of the HTTP request and supports multiple "
                           "input providers, filters, and output formats. It's commonly used "
                           "for directory and file brute-forcing, virtual host discovery, "
                           "parameter fuzzing, and more.",
            "website": "https://github.com/ffuf/ffuf",
            "repository": "https://github.com/ffuf/ffuf"
        }
    }

    # Default options
    opts = {
        "ffuf_path": "",
        "ffuf_wordlist": "",
        "ffuf_concurrency": 40,
        "ffuf_timeout": 10,
        "ffuf_follow_redirects": False,
        "ffuf_match_status_codes": "200-299,301,302,307",
        "ffuf_filter_status_codes": "",
        "ffuf_recursion": False,
        "ffuf_recursion_depth": 0,
        "ffuf_recursion_strategy": "default"
    }

    # Option descriptions
    optdescs = {
        "ffuf_path": "Path to your ffuf binary. Must be set.",
        "ffuf_wordlist": "Path to wordlist file to use for fuzzing. Must be set.",
        "ffuf_concurrency": "Number of concurrent fuzzing threads.",
        "ffuf_timeout": "Seconds to wait before timing out an HTTP request.",
        "ffuf_follow_redirects": "Enable following HTTP redirects?",
        "ffuf_match_status_codes": "Comma-separated list of HTTP status codes to match.",
        "ffuf_filter_status_codes": "Comma-separated list of HTTP status codes to filter out.",
        "ffuf_recursion": "Enable recursive fuzzing (follow FUZZ in URLs)?",
        "ffuf_recursion_depth": "Maximum recursion depth.",
        "ffuf_recursion_strategy": "Recursion strategy: default (redirect-based) or greedy (all matches)."
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
            "LINKED_URL_INTERNAL",
            "URL_FORM",
            "URL_UPLOAD",
            "URL_PASSWORD",
            "VULNERABILITY_GENERAL",
            "TARGET_WEB_CONTENT",
            "WEBSERVER_TECHNOLOGY"
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

        if not self.opts['ffuf_path']:
            self.error("You enabled sfp_tool_ffuf but did not set a path to the tool!")
            self.errorState = True
            return

        if not self.opts['ffuf_wordlist']:
            self.error("You enabled sfp_tool_ffuf but did not set a wordlist path!")
            self.errorState = True
            return

        exe = self.opts["ffuf_path"]
        if self.opts["ffuf_path"].endswith("/"):
            exe = f"{exe}ffuf"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if not os.path.isfile(self.opts["ffuf_wordlist"]):
            self.error(f"Wordlist file does not exist: {self.opts['ffuf_wordlist']}")
            self.errorState = True
            return

        if not SpiderFootHelpers.sanitiseInput(eventData):
            self.debug("Invalid input, skipping.")
            return

        # Don't fuzz the same URL twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already fuzzed.")
            return

        self.results[eventData] = True

        # Try both HTTP and HTTPS since we don't know which scheme the
        # target uses.  Try HTTP first because many internal/test sites
        # don't have HTTPS.
        for scheme in ("http://", "https://"):
            url = f"{scheme}{eventData}"
            self.debug(f"Fuzzing {url}")
            content = self._runFfuf(exe, url, eventData, scheme)
            if content:
                self._processResult(content, event, eventData)
                break  # got results, don't try the other scheme

    def _runFfuf(self, exe, url, originalEvent, scheme):
        """Run ffuf against a URL and return JSON output, or None.

        Args:
            exe: Path to ffuf binary.
            url: Base URL to fuzz (with scheme).
            originalEvent: Original event data for logging.
            scheme: URL scheme being tried.

        Returns:
            JSON output string, or None on failure.
        """
        args = [
            exe,
            "-w", self.opts["ffuf_wordlist"] + ":FUZZ",
            "-u", f"{url}/FUZZ",
            "-mc", self.opts["ffuf_match_status_codes"],
            "-json",
            "-t", str(self.opts["ffuf_concurrency"]),
            "-noninteractive",
        ]

        # Optional filters
        if self.opts.get("ffuf_filter_status_codes", ""):
            args.extend(["-fc", self.opts["ffuf_filter_status_codes"]])

        # Optional timeout
        if int(self.opts.get("ffuf_timeout", 10)) > 0:
            args.extend(["-timeout", str(self.opts["ffuf_timeout"])])

        # Optional redirect following
        if self.opts.get("ffuf_follow_redirects", False):
            args.append("-r")

        # Optional recursion
        if self.opts.get("ffuf_recursion", False):
            args.append("-recursion")
            if self.opts.get("ffuf_recursion_depth", 0) > 0:
                args.extend(["-recursion-depth", str(self.opts["ffuf_recursion_depth"])])
            if self.opts.get("ffuf_recursion_strategy", "default") == "greedy":
                args.extend(["-recursion-strategy", "greedy"])

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            try:
                stdout, stderr = p.communicate(input=None, timeout=int(self.opts["ffuf_timeout"]) + 30)
                if p.returncode == 0:
                    content = stdout.decode(sys.stdout.encoding, errors='replace')
                else:
                    self.debug(f"ffuf returned non-zero exit code for {originalEvent} ({scheme})")
                    return None
            except TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                self.debug(f"Timed out waiting for ffuf to finish on {originalEvent}")
                return None
        except OSError as e:
            self.error(f"Unable to run ffuf: {e}")
            return None

        if not content:
            self.debug(f"ffuf returned no output for {originalEvent} ({scheme})")
            return None

        return content

    def _processResult(self, content, event, originalEvent):
        """Process ffuf JSON output and emit SpiderFoot events.

        Args:
            content: Raw JSON output from ffuf.
            event: Original SpiderFoot event.
            originalEvent: Original event data string.
        """
        for line in content.split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                self.debug(f"Could not parse ffuf JSON line: {line[:200]}")
                continue

            url = data.get("url", "")
            if not url:
                continue

            status_code = data.get("status", 0)
            content_length = data.get("length", 0)
            content_type = data.get("content-type", "")
            redirect_location = data.get("redirectlocation", "")
            host = data.get("host", originalEvent)

            # Determine the FUZZ input value from the URL
            fuzz_path = url.replace(f"https://{host}/", "").replace(f"http://{host}/", "")
            if not fuzz_path:
                fuzz_path = "/"

            # Emit the URL event
            url_data = url
            if status_code:
                url_data += f" [status: {status_code}]"
            if content_length:
                url_data += f" [length: {content_length}]"

            url_evt = SpiderFootEvent(
                "LINKED_URL_INTERNAL", url_data, self.__name__, event
            )
            self.notifyListeners(url_evt)

            # Classify the URL based on path patterns
            path_lower = fuzz_path.lower().rstrip("/")

            # Check for forms
            form_patterns = [
                '/form', '/login', '/signin', '/auth', '/signup',
                '/register', '/contact', '/feedback', '/comment'
            ]
            if any(path_lower.endswith(p) or path_lower == p.lstrip("/") for p in form_patterns):
                form_evt = SpiderFootEvent(
                    "URL_FORM", url_data, self.__name__, event
                )
                self.notifyListeners(form_evt)

            # Check for upload endpoints
            upload_patterns = [
                '/upload', '/uploads', '/file', '/files',
                '/attach', '/attachments', '/media',
                '/images', '/avatar'
            ]
            if any(path_lower.endswith(p) or path_lower == p.lstrip("/") for p in upload_patterns):
                upload_evt = SpiderFootEvent(
                    "URL_UPLOAD", url_data, self.__name__, event
                )
                self.notifyListeners(upload_evt)

            # Check for password/auth endpoints
            password_patterns = [
                '/passwd', '/password', '/pwd', '/credentials',
                '/token', '/oauth', '/api/token', '/reset'
            ]
            if any(path_lower.endswith(p) or path_lower == p.lstrip("/") for p in password_patterns):
                pwd_evt = SpiderFootEvent(
                    "URL_PASSWORD", url_data, self.__name__, event
                )
                self.notifyListeners(pwd_evt)

            # Emit content type if available
            if content_type:
                content_type_evt = SpiderFootEvent(
                    "TARGET_WEB_CONTENT_TYPE", content_type, self.__name__, event
                )
                self.notifyListeners(content_type_evt)

            # Emit web content for JSON/text responses
            if content_type and ('json' in content_type or 'html' in content_type or 'text' in content_type):
                content_evt = SpiderFootEvent(
                    "TARGET_WEB_CONTENT",
                    f"URL: {url}\nContent-Type: {content_type}\nLength: {content_length}",
                    self.__name__, event
                )
                self.notifyListeners(content_evt)

            # Check for technology indicators
            tech_patterns = {
                '/.well-known': 'Well-Known URI',
                '/.well-known/security.txt': 'Security.txt',
                '/sitemap.xml': 'Sitemap',
                '/robots.txt': 'Robots.txt',
                '/.env': 'Environment File',
                '/wp-content': 'WordPress',
                '/wp-admin': 'WordPress Admin',
                '/wp-login.php': 'WordPress Login',
                '/xmlrpc.php': 'WordPress XML-RPC',
                '/wp-json': 'WordPress REST API',
                '/.git': 'Git Repository',
                '/.svn': 'SVN Repository',
                '/.hg': 'Mercurial Repository',
                '/composer.json': 'PHP Composer',
                '/package.json': 'Node.js Package',
                '/pom.xml': 'Maven/Java Project',
                '/build.gradle': 'Gradle/Java Project',
                '/.DS_Store': 'macOS',
                '/server-status': 'Apache Server Status',
                '/server-info': 'Apache Server Info',
                '/phpinfo.php': 'PHP Info',
                '/info.php': 'PHP Info',
                '/test.php': 'PHP Test Page',
                '/cgi-bin': 'CGI Scripts',
                '/actuator': 'Spring Boot Actuator',
                '/swagger': 'Swagger API',
                '/api': 'API Endpoint',
                '/graphql': 'GraphQL Endpoint',
                '/favicon.ico': 'Favicon',
                '/manifest.json': 'Web Manifest',
                '/service-worker.js': 'Service Worker',
                '/crossdomain.xml': 'Flash Crossdomain',
                '/clientaccesspolicy.xml': 'Silverlight Policy',
            }

            for pattern, tech_name in tech_patterns.items():
                if path_lower == pattern.lstrip("/") or path_lower.startswith(pattern.rstrip("/").rstrip("/")):
                    tech_evt = SpiderFootEvent(
                        "WEBSERVER_TECHNOLOGY",
                        tech_name,
                        self.__name__, event
                    )
                    self.notifyListeners(tech_evt)
                    break

            # Check for interesting vulnerabilities
            vuln_patterns = [
                ('/.env', 'Exposed .env file'),
                ('/.git', 'Exposed .git repository'),
                ('/.svn', 'Exposed SVN repository'),
                ('/.hg', 'Exposed Mercurial repository'),
                ('/phpinfo.php', 'PHP info page exposed'),
                ('/server-status', 'Apache server-status exposed'),
                ('/server-info', 'Apache server-info exposed'),
                ('/actuator', 'Spring Boot actuator exposed'),
                ('/xmlrpc.php', 'WordPress XML-RPC exposed'),
                ('/wp-login.php', 'WordPress login page exposed'),
                ('/cgi-bin/', 'CGI-bin directory exposed'),
                ('/test.php', 'PHP test page exposed'),
                ('/info.php', 'PHP info page exposed'),
                ('/backup', 'Backup file/directory'),
                ('/bak', 'Backup file'),
                ('/old', 'Old file/directory'),
                ('/debug', 'Debug endpoint exposed'),
                ('/console', 'Console exposed'),
                ('/admin', 'Admin panel'),
                ('/manager', 'Manager interface'),
                ('/jmx-console', 'JMX Console exposed'),
                ('/web-console', 'Tomcat web-console exposed'),
            ]

            for pattern, vuln_desc in vuln_patterns:
                if path_lower == pattern.lstrip("/") or path_lower.startswith(pattern.rstrip("/")):
                    vuln_evt = SpiderFootEvent(
                        "VULNERABILITY_GENERAL",
                        f"ffuf: {vuln_desc} - {url}",
                        self.__name__, event
                    )
                    self.notifyListeners(vuln_evt)
                    break

            # Check for redirects to interesting locations
            if redirect_location:
                redirect_evt = SpiderFootEvent(
                    "LINKED_URL_INTERNAL",
                    f"{url} -> {redirect_location}",
                    self.__name__, event
                )
                self.notifyListeners(redirect_evt)


# End of sfp_tool_ffuf class
