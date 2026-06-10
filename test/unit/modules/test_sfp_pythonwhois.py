# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         test_sfp_tool_pythonwhois
# Purpose:      Tests for sfp_tool_pythonwhois module
#
# Author:      <your name> <your email>
#
# Created:     2026-06-10
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import pytest
import unittest

from modules.sfp_tool_pythonwhois import sfp_tool_pythonwhois
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModulePythonWhois(unittest.TestCase):
    """Test sfp_tool_pythonwhois module."""

    def test_opts(self):
        """Test options exist and match descriptions."""
        module = sfp_tool_pythonwhois()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        """Test setup creates the module correctly."""
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_pythonwhois()
        module.setup(sf, dict())
        self.assertEqual(module.sf, sf)
        self.assertFalse(module.errorState)

    def test_watchedEvents_should_return_list(self):
        """Test watchedEvents returns a list."""
        module = sfp_tool_pythonwhois()
        module.setup(SpiderFoot(self.default_options), dict())
        self.assertIsInstance(module.watchedEvents(), list)
        self.assertIn("INTERNET_NAME", module.watchedEvents())

    def test_producedEvents_should_return_list(self):
        """Test producedEvents returns a list."""
        module = sfp_tool_pythonwhois()
        module.setup(SpiderFoot(self.default_options), dict())
        self.assertIsInstance(module.producedEvents(), list)
        self.assertIn("DOMAIN_NAME", module.producedEvents())
        self.assertIn("DOMAIN_REGISTRAR", module.producedEvents())
        self.assertIn("RAW_RIR_DATA", module.producedEvents())
        self.assertIn("EMAILADDR", module.producedEvents())

    def test_meta_should_have_valid_keys(self):
        """Test meta dictionary has required keys including toolDetails."""
        module = sfp_tool_pythonwhois()
        self.assertIn('name', module.meta)
        self.assertIn('summary', module.meta)
        self.assertIn('flags', module.meta)
        self.assertIn('useCases', module.meta)
        self.assertIn('categories', module.meta)
        self.assertIn('toolDetails', module.meta)

    def test_handleEvent_should_process_internet_name(self):
        """Test handleEvent processes INTERNET_NAME events."""
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_pythonwhois()
        module.setup(sf, dict())

        # Set up target
        target = SpiderFootTarget("example.com", "INTERNET_NAME")
        module.setTarget(target)

        # Create a ROOT event as source
        root_evt = SpiderFootEvent("ROOT", "example.com", "SpiderFoot", None)

        # Create and dispatch event
        evt = SpiderFootEvent("INTERNET_NAME", "example.com", "test_module", root_evt)
        result = module.handleEvent(evt)
        self.assertIsNone(result)

    def test_handleEvent_should_not_process_self_events(self):
        """Test handleEvent skips events from itself."""
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_pythonwhois()
        module.setup(sf, dict())

        # Set up target
        target = SpiderFootTarget("example.com", "INTERNET_NAME")
        module.setTarget(target)

        # Create a ROOT event as source
        root_evt = SpiderFootEvent("ROOT", "example.com", "SpiderFoot", None)

        # Create event from self
        evt = SpiderFootEvent("INTERNET_NAME", "example.com", "sfp_tool_pythonwhois", root_evt)
        result = module.handleEvent(evt)
        self.assertIsNone(result)

    def test_handleEvent_should_deduplicate(self):
        """Test handleEvent deduplicates events."""
        sf = SpiderFoot(self.default_options)
        module = sfp_tool_pythonwhois()
        module.setup(sf, dict())

        # Set up target
        target = SpiderFootTarget("example.com", "INTERNET_NAME")
        module.setTarget(target)

        # Create a ROOT event as source
        root_evt = SpiderFootEvent("ROOT", "example.com", "SpiderFoot", None)

        # Create and dispatch event twice
        evt = SpiderFootEvent("INTERNET_NAME", "example.com", "test_module", root_evt)
        module.handleEvent(evt)
        module.handleEvent(evt)

    def test_meta_should_have_tool_flag(self):
        """Test meta has the 'tool' flag."""
        module = sfp_tool_pythonwhois()
        self.assertIn("tool", module.meta['flags'])

    def test_meta_should_have_valid_use_cases(self):
        """Test meta has valid use cases."""
        module = sfp_tool_pythonwhois()
        valid_use_cases = ["Footprint", "Passive", "Investigate"]
        for use_case in module.meta['useCases']:
            self.assertIn(use_case, valid_use_cases)

    def test_meta_should_have_valid_categories(self):
        """Test meta has valid categories."""
        module = sfp_tool_pythonwhois()
        valid_categories = [
            "Content Analysis",
            "Crawling and Scanning",
            "DNS",
            "Leaks, Dumps and Breaches",
            "Passive DNS",
            "Public Registries",
            "Real World",
            "Reputation Systems",
            "Search Engines",
            "Secondary Networks",
            "Social Media"
        ]
        for category in module.meta['categories']:
            self.assertIn(category, valid_categories)

    def test_meta_tool_details_should_have_required_fields(self):
        """Test meta toolDetails has required fields."""
        module = sfp_tool_pythonwhois()
        self.assertIn('name', module.meta['toolDetails'])
        self.assertIn('description', module.meta['toolDetails'])
        self.assertIn('website', module.meta['toolDetails'])
        self.assertIn('repository', module.meta['toolDetails'])
