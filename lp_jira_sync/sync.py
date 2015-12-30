#!/usr/bin/env python
from __future__ import unicode_literals

from abc import ABCMeta
from abc import abstractmethod
import ConfigParser
from dateutil import parser
import httplib2
import json
import logging
import os
import six
import sys
import threading

from jira.client import JIRA
from jira.exceptions import JIRAError
from launchpadlib.errors import HTTPError as LPError
from launchpadlib.launchpad import Launchpad
from launchpadlib import uris


SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
SCRIPT_NAME = 'lp_jira_sync'

DEFAULT_CONFIG_FILE = os.environ.get(
    'LP_JIRA_SYNC_CONFIG', os.path.join(SCRIPT_PATH, SCRIPT_NAME + '.conf'))
LP_CACHE_DIR = os.path.expanduser(
    os.environ.get('LP_CACHE_DIR', '~/.launchpadlib/cache'))
LP_CREDENTIALS_FILE = os.environ.get(
    'LP_JIRA_SYNC_CREDENTIALS',
    os.path.join(SCRIPT_PATH, SCRIPT_NAME + '_credentials.conf'))
LP_API_VERSION = 'devel'
DRY_RUN = os.environ.get('DRY_RUN', False)


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


@six.add_metaclass(ABCMeta)
class Client(object):
    def __init__(self):
        self.client = self.authenticate()

    @staticmethod
    def get_str(parameter):
        parameter = parameter or ''
        return parameter.encode('ascii', 'ignore')

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
    def create_bug(self, bug, data):
        pass

    @abstractmethod
    def update_bug(self, bug, data):
        pass


class LpClient(Client):
    status_mapping = {
        'New': 'Open',
        'Incomplete': 'Open',
        'Confirmed': 'Open',
        'Triaged': 'Open',
        'In Progress': 'In Progress',
        'Fix Committed': 'Resolved',
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
        try:
            launchpad = Launchpad.login_with(
                application_name=SCRIPT_NAME,
                service_root=uris.LPNET_SERVICE_ROOT,
                launchpadlib_dir=LP_CACHE_DIR,
                credentials_file=LP_CREDENTIALS_FILE,
                version=LP_API_VERSION,
            )
        except LPError as e:
            log.error(e.content)
            sys.exit(1)
        return launchpad

    def get_bugs(self, project_name, milestone_name, **kwargs):
        bugs = []
        try:
            log.info('Retrieving "%s" project from Launchpad.', milestone_name)
            project = self.client.projects[project_name]
        except KeyError:
            log.error("\"%s\" project wasn't found on Launchpad. "
                      "Skipped.", project_name)
        except LPError as e:
            log.error(e.content)
        else:
            bugs = self.process_project_milestone(project, milestone_name,
                                                  **kwargs)
        return bugs

    def process_project_milestone(self, project, milestone_name, **kwargs):
        bugs_list = []

        milestone = project.getMilestone(name=milestone_name)
        if milestone:
            log.info('Retrieving bugs for "%s" project, "%s" milestone from '
                     'Launchpad.', project.name, milestone_name)
            bug_tasks = milestone.searchTasks(**kwargs)
            log.info(
                'Found %s bugs for "%s" project, "%s" milestone on Launchpad.',
                len(bug_tasks), project.name, milestone_name)

            for task in bug_tasks:
                bugs_list.append(self.process_bug(task))
        else:
            log.error("Closed \"%s\" milestone wasn't found on Launchpad. "
                      "Skipped.", milestone_name)

        return bugs_list

    def process_bug(self, task):
        # TODO
        bug = task.bug
        bug_info = {
            'id': str(bug.id),
            'title': self.get_str(bug.title),
            'description': self.get_str(bug.description),
            'tags': [str(tag) for tag in bug.tags],
            'priority': str(task.importance),
            'status': str(task.status),
            # 'created': bug.date_created,  # TODO
            # 'updated': bug.date_last_updated,
            # 'comments': bug.messages.entries[1:],
            # 'attachments': bug.attachments.entries,
            # 'fix_version': '',
        }

        # if bug.linked_branches.entries:
        #    version = self.get_str(bug.linked_branches.entries[0])
        #    bug.update({'fix_version': version})

        return bug_info

    def create_bug(self, bug, data):
        new_bug = None
        title = data.get('title')

        log.info('Creating new bug on Launchpad: "%s"', title)
        try:
            new_bug = self.client.bugs.createBug(**data)
        except Exception as e:
            log.error('Updating bug failed on Launchpad: "%s"', title)
            raise e
        else:
            log.info('Bug was successfully created on Launchpad: "%s"', title)
        return new_bug

    def update_bug(self, bug, data):
        title = data.get('title')

        log.info('Updating bug on Launchpad: "%s"', title)
        try:
            bug.title = title
            bug.description = data.get('description')
            bug.lp_save()

            bug_task = bug.bug_tasks[0]
            bug_task.status = data.get('status')
            bug_task.importance = data.get('priority')
            bug_task.lp_save()
        except Exception as e:
            log.error('Updating bug failed on Launchpad: "%s"', title)
            raise e
        else:
            log.info('Bug was successfully updated on Launchpad: "%s"', title)


class JiraClient(Client):
    status_mapping = {
        'In Progress': 'In Progress',
        'On Review': 'In Progress',
        'Reopened': 'New',
        'Resolved': 'Fix Committed',
        'Rejected': "Won't Fix",
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
        try:
            jira = JIRA(basic_auth=(config.get('JIRA', 'user'),
                                    config.get('JIRA', 'password')),
                        options={'server': config.get('JIRA', 'url')})
        except JIRAError as e:
            log.error('JIRA connection error. %s (%s)', e.url, e.status_code)
            sys.exit(1)
        return jira

    def get_bugs(self):
        issues = []
        issues_count = 90000
        issue_fields = ','.join([
            'key', 'summary', 'description', 'issuetype', 'priority',
            'status', 'updated', 'comment', 'fixVersions'])
        # TODO tags
        search_string = 'project={0} and issuetype=Bug'.format(
            config.get('JIRA', 'project_key'))

        log.info('Retrieving bugs from JIRA.')
        try:
            issues = self.client.search_issues(search_string,
                                               fields=issue_fields,
                                               maxResults=issues_count)
        except JIRAError as e:
            log.error('JIRA error. %s (%s)', e.url, e.status_code)

        log.info('Found %s bugs on JIRA.', len(issues))

        bugs = []
        for issue in issues:
            bugs.append(self.process_bug(issue))

        return bugs

    def process_bug(self, issue):
        bug = {
            'key': self.get_str(issue.key),
            'title': self.get_str(issue.fields.summary),
            'description': self.get_str(issue.fields.description),
            'priority': self.get_str(issue.fields.priority.name),
            'status': self.get_str(issue.fields.status.name),
            'updated': self.get_date(issue.fields.updated),
            'comments': issue.fields.comment.comments,
            'fix_version': '',
        }

        if issue.fields.fixVersions:
            version = self.get_str(issue.fields.fixVersions[0].name)
            bug.update({'fix_version': version})

        summary = bug['title']
        if 'Launchpad Bug' in summary:
            summary = summary[24:]

        bug.update({'priority_code': bug['priority']['code'],
                    'status_code': bug['status']['code'],
                    'summary': summary})
        return bug

    def create_bug(self, bug, data):
        new_issue = None
        title = data.get('title')
        fields = {
            'project': {
                'key': data.get('project_key')
            },
            'summary': title,
            'description': data.get('description'),
            'issuetype': {
                'name': 'Bug'
            }
        }

        log.info('Creating new bug on JIRA: "%s"', title)
        try:
            new_issue = self.client.create_issue(fields=fields)
        except JIRAError as e:
            log.error('Updating bug failed on JIRA: %s (%s)', e.url,
                      e.status_code)
        else:
            log.info('Bug was successfully created on JIRA: "%s"', title)
        return new_issue

    def update_bug(self, bug, data):
        title = data.get('title')
        new_status_id = None

        log.info('Updating bug on JIRA: "%s"', title)
        try:
            bug.update(**data)

            for status in self.client.transitions(bug):
                if self.get_str(status['name']) == data.pop('new_status'):
                    new_status_id = status['id']

            self.client.transition_issue(
                bug, new_status_id,
                comment='Automatically updated by script.')
        except JIRAError as e:
            log.error('Updating bug failed on JIRA: %s (%s)', title)
            raise e
        else:
            log.info('Bug was successfully updated on JIRA: "%s"', title)


class ThreadSync(threading.Thread):
    def __init__(self, project, milestone, jira_client, lp_client,
                 *args, **kwargs):
        super(ThreadSync, self).__init__(*args, **kwargs)
        self.project = project
        self.milestone = milestone
        self.jira_client = jira_client
        self.lp_client = lp_client

    def run(self):
        """Run bugs synchronization."""
        log.info('Syncing for "%s" project, "%s" milestone.',
                 self.project, self.milestone)

        self.sync_created()
        self.move_bugs_from_lp_to_jira()
        self.move_milestones_from_jira()

    def sync_created(self):
        """Sync already created tasks."""
        # jira_bugs = self.jira_client.get_bugs(status=[])
        # lp_bugs = self.lp_client.get_bugs(
        #     self.project, self.milestone,
        #     status=json.loads(config.get('LP', 'statuses')))

    def move_bugs_from_lp_to_jira(self):
        """Move new bugs from Launchpad to JIRA."""
        pass

    def move_milestones_from_jira(self):
        """Move new milestones from JIRA to Launchpad."""
        pass


def main():
    log.info('Starting to sync.')

    threads = []
    for project in json.loads(config.get('LP', 'projects')):
        for milestone in json.loads(config.get('LP', 'milestones')):
            th = ThreadSync(project, milestone, JiraClient(), JiraClient())
            th.setDaemon(True)
            threads.append(th)

    for th in threads:
        th.start()

    for th in threads:
        th.join()

    log.info('Successfully synced.')


if __name__ == '__main__':
    main()
