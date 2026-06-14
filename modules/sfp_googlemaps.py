# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_googlemaps
# Purpose:      SpiderFoot plug-in to identify historical certificates for a domain
#               from googlemaps.sh, and from this identify hostnames.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     18/03/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import urllib

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_googlemaps(SpiderFootPlugin):

    meta = {
        'name': "Google Maps",
        'summary': "Identifies potential physical addresses and latitude/longitude coordinates.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://cloud.google.com/maps-platform/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://developers.google.com/maps/documentation"
            ],
            'apiKeyInstructions': [
                "Visit https://cloud.google.com/maps-platform/",
                "Register a free Google account",
                "Click on 'Get Started'",
                "Click on 'API'",
                "Select the type of API",
                "Navigate to https://console.cloud.google.com/apis/credentials",
                "Click on 'Credentials'",
                "The API Key will be listed under 'API Keys'"
            ],
            'favIcon': "https://gstatic.com/favicon.ico",
            'logo': "https://gstatic.com/cloud-logo.svg",
            'description': "Explore real-world insights and immersive location experiences.\n"
            "Build with reliable, comprehensive data for 200+ countries and territories.\n"
            "has been done here. If line breaks are needed for breaking up\n"
            "Scale confidently, backed by our infrastructure.",
        }
    }

    opts = {
        "api_key": ""
    }
    optdescs = {
        "api_key": "Google Geocoding API Key."
    }
    results = None
    errorState = False

    def setup(self, sfc, userOpts=None):
        if userOpts is None:
            userOpts = dict()
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['DOMAIN_NAME', 'PHYSICAL_ADDRESS']

    def producedEvents(self):
        return ["PHYSICAL_ADDRESS", "PHYSICAL_COORDINATES", "RAW_RIR_DATA"]

    def query(self, address):
        params = urllib.parse.urlencode({
            'key': self.opts['api_key'],
            'address': address.encode('raw_unicode_escape').decode("ascii", errors='replace')
        })

        res = self.sf.fetchUrl(
            f"https://maps.googleapis.com/maps/api/geocode/json?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.info(f"No location info found for {address}")
            return None

        return res

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        res = self.query(eventData)

        if not res:
            self.debug(f"No information found for {eventData}")
            return

        evt = SpiderFootEvent(
            "RAW_RIR_DATA",
            res['content'],
            self.__name__,
            event
        )
        self.notifyListeners(evt)

        try:
            data = json.loads(res['content'])['results'][0]
        except (json.JSONDecodeError, TypeError, KeyError, IndexError) as e:
            self.debug(f"Error processing JSON response: {e}")
            return

        if srcModuleName == "sfp_googlemaps":
            return

        geometry = data.get('geometry')
        if geometry:
            location = data.get('location')
            if location:
                lat = location.get('lat')
                lng = location.get('lng')
                if lat and lng:
                    evt = SpiderFootEvent(
                        "PHYSICAL_COORDINATES",
                        f"{lat},{lng}",
                        self.__name__,
                        event
                    )
                    self.notifyListeners(evt)

        formatted_address = data.get('formatted_address')
        if formatted_address:
            evt = SpiderFootEvent(
                "PHYSICAL_ADDRESS",
                data['formatted_address'],
                self.__name__,
                event
            )
            self.notifyListeners(evt)

# End of sfp_googlemaps class
