# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_0trace
# Purpose:     SpiderFoot plug-in for using the 0trace tool.
#              Tool: https://github.com/lcamtuf/0trace
#
# Author:      Trent Tanchin <trent@tanchin.org>
#
# Created:     2026-06-11
# Copyright:   (c) Trent Tanchin 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import os.path
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootPlugin, SpiderFootEvent, SpiderFootHelpers


class sfp_tool_0trace(SpiderFootPlugin):

    meta = {
        "name": "Tool - 0trace",
        "summary": "Performs traceroute to a target IP address using ICMP time-exceeded messages.",
        "flags": ["tool"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "name": "0trace",
            "description": "0trace is a traceroute tool that uses ICMP time-exceeded messages "
                           "to discover the path to a target IP address. It sends probes with "
                           "increasing TTL values and sniffs for responses using tcpdump.",
            "website": "https://github.com/lcamtuf/0trace",
            "repository": "https://github.com/lcamtuf/0trace"
        }
    }

    opts = {
        '0trace_path': '',
        'interface': ''
    }

    optdescs = {
        '0trace_path': "Path to the 0trace.sh script. Must be set.",
        'interface': "Network interface to use for sniffing (e.g. eth0). Must be set."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.errorState = False
        self.__dataSource__ = "Target Website"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['IP_ADDRESS']

    def producedEvents(self):
        return ['IP_ADDRESS']

    def handleEvent(self, event):
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {event.eventType}, from {srcModuleName}")

        if self.errorState:
            return

        if srcModuleName == "sfp_tool_0trace":
            self.debug("Skipping event from myself.")
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already scanned.")
            return

        self.results[eventData] = True

        if not self.opts['0trace_path']:
            self.error("You enabled sfp_tool_0trace but did not set a path to 0trace.sh!")
            self.errorState = True
            return

        if not self.opts['interface']:
            self.error("You enabled sfp_tool_0trace but did not set a network interface!")
            self.errorState = True
            return

        exe = self.opts['0trace_path']
        if self.opts['0trace_path'].endswith('/'):
            exe = f"{exe}0trace.sh"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if not SpiderFootHelpers.sanitiseInput(eventData):
            self.debug("Invalid input, refusing to run.")
            return

        args = [
            exe,
            self.opts['interface'],
            eventData
        ]
        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            out, stderr = p.communicate(input=None, timeout=120)
            stdout = out.decode('utf-8', errors='replace')
        except TimeoutExpired:
            p.kill()
            stdout, stderr = p.communicate()
            self.debug(f"Timed out waiting for 0trace to finish on {eventData}")
            return
        except Exception as e:
            self.error(f"Unable to run 0trace: {e}")
            return

        if p.returncode != 0:
            self.error(f"0trace returned non-zero exit code {p.returncode} for {eventData}\nstderr: {stderr}\nstdout: {stdout}")
            return

        if not stdout:
            self.debug(f"0trace returned no output for {eventData}")
            return

        # Emit the target IP as reachable if the trace succeeded
        evt = SpiderFootEvent("IP_ADDRESS", eventData, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_tool_0trace class
