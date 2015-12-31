from __future__ import unicode_literals

import unittest

from lp_jira_sync import sync


class TestSync(unittest.TestCase):

    def setUp(self):
        self.lp_client = sync.LpClient()
        self.jira_client = sync.JiraClient()

    def test_config(self):
        self.assertTrue(sync.config.has_section('JIRA'))
        self.assertTrue(sync.config.has_section('LP'))
