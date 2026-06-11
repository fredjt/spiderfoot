# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_altdns
# Purpose:     SpiderFoot plug-in for using the altdns tool.
#              Tool: https://github.com/infosec-au/altdns
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     2026-06-11
# Copyright:   (c) Steve Micallef 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import os
import tempfile
from contextlib import suppress
from shutil import which
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin, SpiderFootHelpers


class sfp_tool_altdns(SpiderFootPlugin):

    meta = {
        'name': "Tool - altdns",
        'summary': "Discover subdomains that conform to patterns using a local altdns installation.",
        'flags': ["tool"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["DNS"],
        'toolDetails': {
            'name': "altdns",
            'description': "altdns is a DNS reconnaissance tool that generates permutations of known "
            "subdomains based on a wordlist and resolves them to discover active subdomains. "
            "It can identify subdomains that conform to organizational naming patterns, "
            "potentially revealing development environments, staging sites, or other "
            "infrastructure not otherwise documented.",
            'website': "https://github.com/infosec-au/altdns",
            'repository': "https://github.com/infosec-au/altdns"
        },
    }

    # Default options
    opts = {
        'altdns_path': "",
        'wordlist': "",
        'threads': 20,
        'add_number_suffix': True,
        'ignore_existing': True,
        'skipwildcards': True,
        'dnsserver': ""
    }

    # Option descriptions
    optdescs = {
        'altdns_path': "Path to the altdns binary. If unset, 'altdns' is looked up in PATH.",
        'wordlist': "Path to the wordlist file (one word per line). If unset, the bundled "
                    "altdns-words.txt is used.",
        'threads': "Maximum number of concurrent DNS resolution threads.",
        'add_number_suffix': "Enable generation of number suffixes (e.g. www0, www-0).",
        'ignore_existing': "Skip domains already present in the input file during generation.",
        'skipwildcards': "Skip domains whose TLD has wildcard DNS enabled.",
        'dnsserver': "Custom DNS resolver IP address to use instead of system default."
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.__dataSource__ = "DNS"

        # Resolve bundled wordlist path once
        if not self.opts['wordlist']:
            self.__wordlistPath = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "spiderfoot", "dicts", "altdns-words.txt"
            )
        else:
            self.__wordlistPath = self.opts['wordlist']

        # Resolve altdns binary path once
        if not self.opts['altdns_path']:
            self.__altdnsPath = which('altdns')
            if not self.__altdnsPath:
                self.error("You enabled sfp_tool_altdns but altdns is not installed "
                           "and altdns_path is not set!")
                self.errorState = True
        else:
            self.__altdnsPath = self.opts['altdns_path']

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['DOMAIN_NAME']

    # What events this module produces
    def producedEvents(self):
        return ["DOMAIN_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if srcModuleName == self.__name__:
            self.debug("Skipping event from myself.")
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already scanned.")
            return

        self.results[eventData] = True

        # Sanitize domain name
        if not SpiderFootHelpers.sanitiseInput(eventData):
            self.error("Invalid input, refusing to run.")
            return

        # Extract keyword and TLD
        dom = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
        if not dom:
            self.error(f"Could not extract keyword from domain: {eventData}")
            return

        tld = eventData.split(dom + ".")[-1]

        # Check if the TLD has wildcards before testing
        if self.opts['skipwildcards'] and self.sf.checkDnsWildcard(tld):
            self.debug(f"Wildcard DNS detected on {eventData} TLD: {tld}")
            return

        # Validate cached paths
        if not os.path.isfile(self.__wordlistPath):
            self.error(f"Wordlist file not found: {self.__wordlistPath}")
            self.errorState = True
            return

        if not self.__altdnsPath:
            self.error("altdns binary not found during setup.")
            self.errorState = True
            return

        if not os.path.isfile(self.__altdnsPath):
            self.error(f"altdns file does not exist: {self.__altdnsPath}")
            self.errorState = True
            return

        # Create temp files for input, output, and resolved results
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as inf:
                inf.write(eventData + "\n")
                input_file = inf.name

            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as outf:
                output_file = outf.name

            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as resf:
                results_file = resf.name
            # Build command
            cmd = [
                self.__altdnsPath,
                '-i', input_file,
                '-o', output_file,
                '-w', self.__wordlistPath,
                '-r',          # enable resolution
                '-s', results_file,
                '-t', str(self.opts['threads'])
            ]

            if self.opts['add_number_suffix']:
                cmd.append('-n')

            if self.opts['ignore_existing']:
                cmd.append('-e')

            if self.opts['dnsserver']:
                cmd.extend(['-d', self.opts['dnsserver']])

            # Run altdns
            p = Popen(cmd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=300)

            if p.returncode != 0:
                self.error(f"altdns returned non-zero exit code {p.returncode} for {eventData}\n"
                           f"stderr: {stderr.decode('utf-8', errors='replace')}\n"
                           f"stdout: {stdout.decode('utf-8', errors='replace')}")
                return

            # Parse resolved results
            if not os.path.getsize(results_file):
                self.debug(f"altdns returned no resolved subdomains for {eventData}")
                return

            with open(results_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Format: domain:resolved_value
                    domain = line.split(':')[0]
                    if not domain:
                        continue

                    # Skip if it matches the scan target
                    if self.getTarget().matches(domain, includeChildren=False):
                        continue

                    # Skip if already scanned
                    if domain in self.results:
                        continue

                    self.results[domain] = True
                    evt = SpiderFootEvent("DOMAIN_NAME", domain,
                                          self.__name__, event)
                    self.notifyListeners(evt)

        except TimeoutExpired:
            p.kill()
            p.communicate()
            self.debug(f"Timed out waiting for altdns to finish on {eventData}")
            return
        except Exception as e:
            self.error(f"Unable to run altdns: {e}")
            return
        finally:
            # Clean up temp files
            for fpath in [input_file, output_file, results_file]:
                with suppress(Exception):
                    os.unlink(fpath)

# End of sfp_tool_altdns class
