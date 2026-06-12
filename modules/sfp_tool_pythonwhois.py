# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_pythonwhois
# Purpose:      SpiderFoot plug-in for querying python-whois for domain registration details.
#
# Author:      Trent Tanchin <trent@tanchin.org>
#
# Created:     2026-06-10
# Copyright:   (c) Trent Tanchin 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_pythonwhois(SpiderFootPlugin):

    meta = {
        'name': "Tool - Python Whois",
        'summary': "Query python-whois for domain registration details.",
        'flags': ["tool"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Public Registries"],
        'toolDetails': {
            'name': "python-whois",
            'description': "python-whois is a pure Python WHOIS querying library for Python 2.7+ and Python 3.\n"
            "It parses WHOIS response data and returns a dict-like object with domain registration details\n"
            "including registrar, name servers, creation/expiry dates, and contact information.\n",
            'website': "https://github.com/richardpenman/whois",
            'repository': "https://github.com/richardpenman/whois"
        }
    }

    # Default options
    opts = {
        'verify': True,
    }

    # Option descriptions
    optdescs = {
        'verify': "Verify the domain still resolves before querying WHOIS?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DOMAIN_NAME", "DOMAIN_REGISTRAR", "DOMAIN_WHOIS", "RAW_RIR_DATA", "EMAILADDR"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if srcModuleName == "sfp_tool_pythonwhois":
            self.debug("Skipping event from myself.")
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return
        self.results[eventData] = True

        # Verify the domain still resolves if the option is enabled
        if self.opts['verify']:
            if not self.sf.resolveHost(eventData):
                self.debug(f"Domain {eventData} does not resolve, skipping.")
                return

        # Build the wrapper script to invoke python-whois via subprocess
        script = (
            "import whois, json, sys; "
            "data = whois.whois(sys.argv[1]); "
            "print(json.dumps(data))"
        )

        timeout = 30
        try:
            p = Popen(
                ["python3", "-c", script, eventData],
                stdin=PIPE, stdout=PIPE, stderr=PIPE
            )
            try:
                stdout, stderr = p.communicate(timeout=timeout)
            except TimeoutExpired:
                p.kill()
                p.communicate()
                self.debug("Timed out waiting for python-whois to finish.")
                return

            content = stdout.decode('utf-8', errors='replace').strip()
            if p.returncode != 0 or not content:
                self.debug(f"python-whois returned no data for {eventData}.")
                return

            import json as jsonmod
            w = jsonmod.loads(content)
        except Exception as e:
            self.error(f"Error running python-whois for {eventData}: {e}")
            return

        if not w:
            self.debug(f"No whois data returned for {eventData}.")
            return

        # Store raw RIR data
        try:
            raw_data = str(w)
            raw_evt = SpiderFootEvent("RAW_RIR_DATA", raw_data, self.__name__, event)
            self.notifyListeners(raw_evt)
        except Exception as e:
            self.error(f"Error processing raw whois data for {eventData}: {e}")
            return

        # Extract domain name
        domain_name = w.get('domain_name')
        if domain_name:
            # domain_name can be a string or a list
            if isinstance(domain_name, list):
                for dn in domain_name:
                    if dn and str(dn).strip():
                        evt = SpiderFootEvent("DOMAIN_NAME", str(dn).strip().upper(), self.__name__, event)
                        self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("DOMAIN_NAME", str(domain_name).strip().upper(), self.__name__, event)
                self.notifyListeners(evt)

        # Extract registrar information
        registrar = w.get('registrar')
        if registrar:
            if isinstance(registrar, list):
                for reg in registrar:
                    if reg and str(reg).strip():
                        evt = SpiderFootEvent("DOMAIN_REGISTRAR", str(reg).strip(), self.__name__, event)
                        self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("DOMAIN_REGISTRAR", str(registrar).strip(), self.__name__, event)
                self.notifyListeners(evt)

        # Extract name servers
        name_servers = w.get('name_servers')
        if name_servers:
            if isinstance(name_servers, list):
                for ns in name_servers:
                    if ns and str(ns).strip():
                        evt = SpiderFootEvent("DOMAIN_NAME", str(ns).strip().lower(), self.__name__, event)
                        self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("DOMAIN_NAME", str(name_servers).strip().lower(), self.__name__, event)
                self.notifyListeners(evt)

        # Extract emails
        emails = w.get('emails')
        if emails:
            if isinstance(emails, list):
                for email in emails:
                    if email and str(email).strip():
                        evt = SpiderFootEvent("EMAILADDR", str(email).strip().lower(), self.__name__, event)
                        self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("EMAILADDR", str(emails).strip().lower(), self.__name__, event)
                self.notifyListeners(evt)


# End of sfp_tool_pythonwhois class
