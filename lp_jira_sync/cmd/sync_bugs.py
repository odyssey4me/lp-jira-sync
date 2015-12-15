import json
import httplib2
import logging
import re
from dateutil import parser

from jira.client import JIRA
from launchpadlib.launchpad import Launchpad

from lp_jira_sync.config import settings
from lp_jira_sync.db import db
from lp_jira_sync import lp_client

log = logging.getLogger(__name__)

httplib2.debuglevel = 0


def get_jira_bugs(url, user, password, project):
    pass


def get_launchpad_bugs(project):
    pass


def sync_jira_with_launchpad(url, user, password, project, project_key,
                             milestones):
    template = 'Launchpad Bug #{0}: '

    jira_bugs = get_jira_bugs(url, user, password, project)
    launchpad_bugs = get_launchpad_bugs(project)

    jira = JIRA(basic_auth=(user, password), options={'server': url})
    launchpad = Launchpad.login_with(project, 'production')

    # TODO: Sync already create tasks
    # TODO: Move new bugs from launchpad to JIRA
    # TODO: Move new milestones from JIRA to launchpad


def run():
    log.info("Starting to sync")

    for project in json.loads(settings.get('LP', 'projects')):
        log.info("Syncing for {0} project".format(project))
        sync_jira_with_launchpad(url=settings.get('JIRA', 'url'),
                                 user=settings.get('JIRA', 'user'),
                                 password=settings.get('JIRA', 'password'),
                                 project=project,
                                 project_key=settings.get('JIRA',
                                                          'project_key'),
                                 milestones=json.loads(
                                     settings.get('LP', 'milestones')))
    log.info("Successfully synced")
