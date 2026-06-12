# -------------------------------------------------------------------------------
# Name:        sfp_venmo
# Purpose:     Gather user information from Venmo API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-07-16
# Copyright:   (c) bcoles 2019
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_venmo(SpiderFootPlugin):

    meta = {
        'name': "Venmo",
        'summary': "Gather user information from Venmo API.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://venmo.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'favIcon': "https://venmo.com/apple-touch-icon.png",
            'logo': "https://venmo.com/apple-touch-icon.png",
            'description': "Venmo is a digital wallet for sending money and making purchases.",
        }
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['USERNAME']

    # What events this module produces
    def producedEvents(self):
        return ['RAW_RIR_DATA', 'HUMAN_NAME']

    # Query Venmo API
    def query(self, qry):
        res = self.sf.fetchUrl('https://api.venmo.com/v1/users/' + qry,
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.debug('No response from api.venmo.com')
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        json_data = data.get('data')

        if not json_data:
            self.debug(qry + " is not a valid Venmo username")
            return None

        return json_data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        data = self.query(eventData)

        if not data:
            return

        display_name = data.get('display_name')
        if " " not in display_name:
            if not data.get('first_name') or not data.get('last_name'):
                return
            display_name = data['first_name'] + " " + data['last_name']

        if display_name:
            evt = SpiderFootEvent('HUMAN_NAME', display_name, self.__name__, event)
            self.notifyListeners(evt)

            evt = SpiderFootEvent('RAW_RIR_DATA', str(data),
                                  self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_venmo class
