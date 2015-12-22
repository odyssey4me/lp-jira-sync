#!/usr/bin/env python
from __future__ import unicode_literals

from abc import ABCMeta, abstractmethod
import ConfigParser
from dateutil import parser
import httplib2
import json
import logging
import os
import re

from jira.client import JIRA
from launchpadlib.launchpad import Launchpad
from launchpadlib import uris


SCRIPT_NAME = 'lp_jira_sync'
DEFAULT_CONFIG_FILE = os.environ.get('LP_JIRA_SYNC_CONFIG',
                                     SCRIPT_NAME + '.conf')
LP_CACHE_DIR = os.path.expanduser(
    os.environ.get('LP_CACHE_DIR', '~/.launchpadlib/cache'))
LP_CREDENTIALS_FILE = SCRIPT_NAME + '_credentials.conf'
LP_API_VERSION = 'devel'
DRY_RUN = os.environ.get('DRY_RUN', 'False')


def setup_logger():
    logging.basicConfig(format='[%(asctime)s] --%(levelname)s-- %(message)s',
                        datefmt="%Y-%m-%d %H:%M:%S",
                        level=logging.INFO)
    httplib2.debuglevel = 0
    return logging.getLogger('lp_jira_sync')


def setup_config():
    cfg = ConfigParser.ConfigParser()
    cfg.read(DEFAULT_CONFIG_FILE)
    return cfg


log = setup_logger()

config = setup_config()


class Client(object):
    __metaclass__ = ABCMeta

    def __init__(self, project, milestone):
        self.project = project
        self.milestone = milestone

    @staticmethod
    def get_str(parameter):
        parameter = parameter or ''
        return str(parameter.encode('ascii', 'ignore'))

    @staticmethod
    def get_date(parameter):
        return parser.parse(parameter)

    @staticmethod
    def str2bool(v):
        return v.lower() in {'yes', 'true', 't', '1'}

    @abstractmethod
    def authenticate(self):
        pass

    @abstractmethod
    def get_bugs(self, statuses=None):
        pass


class LpClient(Client):
    status_mapping = {
        'New': 'Open',
        'Invalid': 'Closed',
        "Won't Fix": 'Closed',
        'Confirmed': 'Open',
        'Triaged': 'Open',
        'In Progress': 'In Progress',
        'Fix Commited': 'Resolved',
    }

    priority_mapping = {
        'Critical': 'Critical',
        'High': 'Major',
        'Medium': 'Major',
        'Low': 'Nice to have',
        'Wishlist': 'Nice to have',
        'Undecided': '',
    }

    def authenticate(self):
        log.info('Launchpad API client authentication.')
        try:
            launchpad = Launchpad.login_with(
                application_name=SCRIPT_NAME,
                service_root=uris.LPNET_SERVICE_ROOT,
                launchpadlib_dir=LP_CACHE_DIR,
                credentials_file=LP_CREDENTIALS_FILE,
                version=LP_API_VERSION,
            )
        except Exception as exc:
            log.error("Can't login to Launchpad or server is down.")
            raise exc
        return launchpad

    def get_bugs(self, statuses=None):
        launchpad = self.authenticate()
        bugs = []
        try:
            project = launchpad.projects[self.project]
            if not project:
                raise ValueError
        except (KeyError, ValueError):
            log.error("Project %s wasn't found on Launchpad. Skipped.",
                      self.project)
        else:
            bugs = self.process_milestone_on_project(project, statuses)
        return bugs

    def process_milestone_on_project(self, project, statuses):
        bugs_list = []
        log.info('Retrieving milestone %s  on Launchpad.', self.milestone)
        milestone = project.getMilestone(name=self.milestone)
        if milestone:
            log.info('Retrieving bugs for milestone %s on Launchpad.',
                     self.milestone)
            bug_tasks = milestone.searchTasks(status=statuses)
            log.info('Found %s bugs on Launchpad.', len(bug_tasks))

            for bug_task in bug_tasks:
                bugs_list.append(self.process_bug(bug_task))
        else:
            log.info("Closed milestone %s wasn't found on Launchpad. Skipped.",
                     self.milestone)
        return bugs_list

    def process_bug(self, bug_task):
        bug = bug_task.bug
        res = {'id': self.get_str(bug.id),
               'title': self.get_str(bug.title),
               'description': self.get_str(bug.description),
               'tags': bug.tags,
               'priority': self.get_str(bug_task.importance),
               'status': self.get_str(bug_task.status),
               'created': bug.date_created,  # TODO
               'updated': bug.date_last_updated,
               #'comments': bug.messages.entries[1:],
               #'attachments': bug.attachments.entries,
               'fix_version': ''}

        #if bug.linked_branches.entries:
        #    version = get_str(bug.linked_branches.entries[0])
        #    bug.update({'fix_version': version})

        bug.update({'priority_code': bug['priority']['code'],
                    'status_code': bug['status']['code']})
        return res


class JiraClient(Client):
    status_mapping = {
        'In Progress': 'In Progress',
        'On Review': 'In Progress',
        'Reopened': 'New',
        'Resolved': 'Fix Committed',
        'Rejected': 'Invalid',
        'Closed': 'Fix Released',
    }

    priority_mapping = {
        'Blocker': 'Critical',
        'Critical': 'Critical',
        'Major': 'Medium',
        'Nice to have': 'Low',
        'Some day': 'Low',
    }

    def authenticate(self):
        return JIRA(basic_auth=(config.get('JIRA', 'user'),
                                config.get('JIRA', 'password')),
                    options={'server': config.get('JIRA', 'url')})

    def get_bugs(self, statuses=None):
        issues_count = 900000
        issue_fields = 'key,summary,description,issuetype,' + \
                       'priority,status,updated,comment,fixVersions'

        search_string = 'project={0} and issuetype=Bug'.format(self.project)
        jira = self.authenticate()
        issues = jira.search_issues(search_string, fields=issue_fields,
                                    maxResults=issues_count)
        bugs = []
        for issue in issues:
            bug = {'key': self.get_str(issue.key),
                   'title': self.get_str(issue.fields.summary),
                   'description': self.get_str(issue.fields.description),
                   'priority': self.get_str(issue.fields.priority.name),
                   'status': self.get_str(issue.fields.status.name),
                   'updated': self.get_date(issue.fields.updated),
                   'comments': issue.fields.comment.comments,
                   'fix_version': ''}

            if issue.fields.fixVersions:
                version = self.get_str(issue.fields.fixVersions[0].name)
                bug.update({'fix_version': version})

            summary = bug['title']
            if 'Launchpad Bug' in summary:
                summary = summary[24:]

            bug.update({'priority_code': bug['priority']['code'],
                        'status_code': bug['status']['code'],
                        'summary': summary})

            bugs.append(bug)

        print 'Found ' + str(len(bugs)) + ' bugs in JIRA'
        return bugs


def sync_jira_with_launchpad(project, milestone):
    log.info('Syncing for %s project, %s milestone.', project, milestone)

    jira_client = JiraClient(project, milestone)
    lp_client = LpClient(project, milestone)

    # Sync already created tasks
    # jira_bugs = jira_client.get_bugs(statuses=[])
    launchpad_bugs = lp_client.get_bugs(statuses=[
        'New', 'Incomplete', 'Opinion', 'Invalid', "Won't Fix", 'Confirmed',
        'Triaged', 'In Progress', 'Fix Commited'])

    # TODO: Move new bugs from Launchpad to JIRA
    # jira_bugs = jira_client.get_bugs()
    # launchpad_bugs = lp_client.get_bugs(statuses=[
    #     'New', 'Confirmed', 'Triaged'])

    # TODO: Move new milestones from JIRA to Launchpad
    # jira_bugs = jira_client.get_bugs()
    # launchpad_bugs = lp_client.get_bugs(statuses=[
    #     'New', 'Confirmed', 'Triaged', 'In Progress','Fix Commited'])


def main():
    log.info('Starting to sync.')

    for project in json.loads(config.get('LP', 'projects')):
        for milestone in json.loads(config.get('LP', 'milestones')):
            sync_jira_with_launchpad(project, milestone)
    log.info('Successfully synced.')


if __name__ == '__main__':
    main()
