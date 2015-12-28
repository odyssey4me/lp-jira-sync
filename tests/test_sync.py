from __future__ import unicode_literals

import unittest

from lp_jira_sync import sync


class TestSync(unittest.TestCase):

    def setUp(self):
        project = 'fuel'
        milestone = '7.0-updates'

        self.lp_client = sync.LpClient(project, milestone)
        self.jira_client = sync.JiraClient(project, milestone)

    def test_config(self):
        self.assertTrue(sync.config.has_section('JIRA'))
        self.assertTrue(sync.config.has_section('LP'))

    def test_lp_authenticate(self):
        launchpad_bugs = self.lp_client.get_bugs()
        self.assertGreater(len(launchpad_bugs), 0)

    def test_jira_authenticate(self):
        jira_bugs = self.jira_client.get_bugs()
        self.assertGreater(len(jira_bugs), 0)
