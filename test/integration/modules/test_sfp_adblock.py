import hashlib
import os
import pytest
import unittest

from modules.sfp_adblock import sfp_adblock
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget
from spiderfoot.helpers import SpiderFootHelpers


@pytest.mark.usefixtures
class TestModuleIntegrationAdblock(unittest.TestCase):

    # Minimal AdBlock Plus blocklist with a rule matching example.local scripts
    _MINIMAL_BLOCKLIST = """\
[Version]
2026.06.11.1310
! Minimal blocklist for testing
||example.local/lib/ad.js$third-party
"""

    def setUp(self):
        # Clear any cached adblock blocklist from previous test runs
        cache_dir = SpiderFootHelpers.cachePath()
        cache_key = hashlib.sha224(b"adblock_https://example.local/testblocklist").hexdigest()
        cache_file = os.path.join(cache_dir, cache_key)
        if os.path.exists(cache_file):
            os.remove(cache_file)

    def test_handleEvent_event_data_provider_javascript_url_matching_ad_filter_should_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_adblock()
        module.setup(sf, {'blocklist': 'https://example.local/testblocklist'})

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'URL_ADBLOCKED_EXTERNAL'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = 'https://example.local/lib/ad.js'
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_adblock)

        def mock_fetchUrl(url, **kwargs):
            if url == 'https://example.local/testblocklist':
                return {'code': "200", 'content': TestModuleIntegrationAdblock._MINIMAL_BLOCKLIST}
            return {'code': "404", 'content': None}

        sf.fetchUrl = mock_fetchUrl

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'PROVIDER_JAVASCRIPT'
        event_data = 'https://example.local/lib/ad.js'
        event_module = 'example module'
        source_event = evt

        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    def test_handleEvent_event_data_external_url_matching_ad_filter_should_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_adblock()
        module.setup(sf, {'blocklist': 'https://example.local/testblocklist'})

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'URL_ADBLOCKED_EXTERNAL'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = 'https://example.local/lib/ad.js'
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_adblock)

        def mock_fetchUrl(url, **kwargs):
            if url == 'https://example.local/testblocklist':
                return {'code': "200", 'content': TestModuleIntegrationAdblock._MINIMAL_BLOCKLIST}
            return {'code': "404", 'content': None}

        sf.fetchUrl = mock_fetchUrl

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'LINKED_URL_EXTERNAL'
        event_data = 'https://example.local/lib/ad.js'
        event_module = 'example module'
        source_event = evt

        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    def test_handleEvent_event_data_external_url_not_matching_ad_filter_should_not_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_adblock()
        module.setup(sf, {'blocklist': 'https://example.local/testblocklist'})

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_adblock)

        def mock_fetchUrl(url, **kwargs):
            if url == 'https://example.local/testblocklist':
                return {'code': "200", 'content': TestModuleIntegrationAdblock._MINIMAL_BLOCKLIST}
            return {'code': "404", 'content': None}

        sf.fetchUrl = mock_fetchUrl

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'LINKED_URL_EXTERNAL'
        event_data = 'https://example.local/lib/example.js'
        event_module = 'example module'
        source_event = evt

        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)
