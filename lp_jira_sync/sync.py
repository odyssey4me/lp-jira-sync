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
import sys
import threading

from jira.client import JIRA
from jira.exceptions import JIRAError
from launchpadlib.errors import HTTPError as LPError
from launchpadlib.launchpad import Launchpad
from launchpadlib import uris


SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
SCRIPT_NAME = 'lp_jira_sync'

# Path to config file
DEFAULT_CONFIG_FILE = os.environ.get(
    'LP_JIRA_SYNC_CONFIG', os.path.join(SCRIPT_PATH, SCRIPT_NAME + '.conf'))

# The directory used to store cached data obtained from Launchpad
LP_CACHE_DIR = os.path.expanduser(
    os.environ.get('LP_CACHE_DIR', '~/.launchpadlib/cache'))

# The path to a file in which to store this user's OAuth access token
LP_CREDENTIALS_FILE = os.environ.get(
    'LP_JIRA_SYNC_CREDENTIALS',
    os.path.join(SCRIPT_PATH, SCRIPT_NAME + '_credentials.conf'))

# Dry-run mode to run the script without any actions on data
DRY_RUN = os.environ.get('DRY_RUN', '').lower() in {'true', 't', '1'}


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

    def __init__(self):
        self.client = self.authenticate()

    @staticmethod
    def get_str(parameter):
        parameter = parameter or ''
        return parameter.encode('ascii', 'ignore')

    @staticmethod
    def get_date(parameter):
        return parser.parse(parameter)

    @abstractmethod
    def authenticate(self):
        pass

    @abstractmethod
    def create_bug(self, data):
        pass

    @abstractmethod
    def update_bug(self, bug, data):
        pass


class LpClient(Client):
    lp_api_version = 'devel'

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

    @staticmethod
    def clean_duplicates(bugs):
        titles = set()
        filtered_bugs = []
        for bug in bugs:
            if bug['title'] not in titles:
                titles.add(bug['title'])
                filtered_bugs.append(bug)
        return filtered_bugs

    def authenticate(self):
        try:
            launchpad = Launchpad.login_with(
                application_name=SCRIPT_NAME,
                service_root=uris.LPNET_SERVICE_ROOT,
                launchpadlib_dir=LP_CACHE_DIR,
                credentials_file=LP_CREDENTIALS_FILE,
                version=self.lp_api_version,
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
            log.error("\"%s\" project wasn't found on Launchpad. Skipped.",
                      project_name)
        except LPError as e:
            log.error(e.content)
        else:
            bugs = self.process_project_milestone(project, milestone_name,
                                                  **kwargs)
        return bugs

    def process_project_milestone(self, project, milestone_name, **kwargs):
        bugs = []

        milestone = project.getMilestone(name=milestone_name)
        if milestone:
            log.info('Retrieving bugs for "%s" project, "%s" milestone from '
                     'Launchpad.', project.name, milestone_name)
            bug_tasks = milestone.searchTasks(**kwargs)
            log.info(
                'Found %s bugs for "%s" project, "%s" milestone on Launchpad.',
                len(bug_tasks), project.name, milestone_name)

            for task in bug_tasks:
                bugs.append(self.process_bug(task))
        else:
            log.error("Closed \"%s\" milestone wasn't found on Launchpad. "
                      "Skipped.", milestone_name)
        return bugs

    def process_bug(self, task):
        # TODO other fields?
        bug = task.bug
        bug_info = {
            'key': str(bug.id),
            'title': self.get_str(bug.title),
            'summary': self.get_str(bug.title),
            'description': self.get_str(bug.description),
            'tags': set([str(tag) for tag in bug.tags]),
            'priority': str(task.importance),
            'status': str(task.status),
            'updated': bug.date_last_updated,
            # 'attachments': bug.attachments.entries,
        }
        return bug_info

    def create_bug(self, data):
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
        'Open': 'New',
        'Reopened': 'New',
        'In Progress': 'In Progress',
        'On Review': 'In Progress',
        'Code Review': 'In Progress',
        'Rejected': "Won't Fix",
        'Resolved': 'Fix Committed',
        'Verification': 'Fix Committed',
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

    def get_bugs(self, project_name, milestone_name):
        bugs = []
        max_results = 90000
        issue_fields = ','.join([
            'key', 'summary', 'description', 'issuetype', 'priority',
            'status', 'labels', 'updated'])
        search_string = ('project="{0}" and issueType="Bug" and labels in '
                         '("{1}")').format(project_name, milestone_name)

        # FIXME debug
        # search_string = 'project="{0}" and issueType="Bug"'.format(project_name, milestone_name)

        log.info('Retrieving bugs for "%s" project, "%s" milestone from JIRA.',
                 project_name, milestone_name)
        try:
            issues = self.client.search_issues(search_string,
                                               fields=issue_fields,
                                               maxResults=max_results)
        except JIRAError as e:
            log.error('JIRA error. %s (%s)', e.url, e.status_code)
        else:
            log.info('Found %s bugs for "%s" project, "%s" milestone on JIRA.',
                     len(issues), project_name, milestone_name)

            for issue in issues:
                bugs.append(self.process_bug(issue))
        return bugs

    def process_bug(self, issue):
        # TODO other fields?
        bug = {
            'key': str(issue.key),
            'title': self.get_str(issue.fields.summary),
            'summary': self.get_str(issue.fields.summary),
            'description': self.get_str(issue.fields.description),
            'tags': set([str(lbl) for lbl in issue.fields.labels]),
            'priority': str(issue.fields.priority.name),
            'status': str(issue.fields.status.name),
            'updated': self.get_date(issue.fields.updated),
        }

        # FIXME wtf?
        if 'Launchpad Bug' in bug['summary']:
            bug['summary'] = bug['summary'][24:]

        return bug

    def create_bug(self, data):
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


class ThreadSyncBugs(threading.Thread):
    def __init__(self, project, milestone, jira, lp):
        super(ThreadSyncBugs, self).__init__()

        self.project = project
        self.milestone = milestone
        self.jira_project = json.loads(
            config.get('JIRA', 'projects')).get(self.project)

        self.prefix_title = 'Launchpad Bug #{0}: '

        self.jira = jira
        self.lp = lp

    def run(self):
        """Run bugs synchronization."""
        log.info('Syncing for "%s" project, "%s" milestone.',
                 self.project, self.milestone)

        if DRY_RUN:
            log.warn('Dry run mode active. No changes will be performed.')
            log.warn(40 * '-')

        # FIXME debug
        self.sync_created_bugs()
        self.move_bugs_from_lp_to_jira()
        self.move_milestones_from_jira()

    @staticmethod
    def is_bugs_match(lbug, jbug):
        return (lbug['title'] in jbug['title'] or
                lbug['key'] in jbug['title'])

    def sync_created_bugs(self):
        """Sync already created tasks."""
        jira_bugs = self.jira.get_bugs(self.jira_project, self.milestone)
        lp_bugs = self.lp.get_bugs(
            self.project, self.milestone,
            status=json.loads(config.get('LP', 'sync_statuses')))

        for jbug in jira_bugs:
            for lbug in lp_bugs:
                if not self.is_bugs_match(lbug, jbug):
                    continue

                for param in ['summary', 'description', 'tags', 'status_code',
                              'priority_code']:
                    if jbug[param] == lbug[param]:
                        continue

                    # Changed in LP
                    if jbug['updated'] < lbug['updated']:

                        new_title = ''
                        if not lbug['key'] in jbug['title']:
                            new_title = self.prefix_title.format(lbug['key'])
                        new_title += lbug['title']
                        data = {
                            'title': new_title,
                            'description': lbug['description'],
                            'priority': lbug['priority']['jira'],
                            'status': lbug['status']['jira'],
                        }

                        if not DRY_RUN:
                            self.jira.update_bug(
                                self.jira.issue(jbug['key']),
                                data)

                    # Changed in JIRA
                    else:
                        new_title = jbug['title']
                        if 'Launchpad Bug' in new_title:
                            new_title = str(new_title[24:])
                        data = {
                            'title': new_title,
                            'description': jbug['description'],
                            'priority': jbug['priority']['launchpad'],
                            'status': jbug['status']['launchpad'],
                        }

                        if not DRY_RUN:
                            self.lp.update_bug(
                                self.lp.bugs[lbug['key']],
                                data)
                    break
                break

    def move_bugs_from_lp_to_jira(self):
        """Move new bugs from Launchpad to JIRA."""
        jira_bugs = self.jira.get_bugs(self.jira_project, self.milestone)
        lp_bugs = self.lp.get_bugs(
            self.project, self.milestone,
            status=json.loads(config.get('LP', 'export_statuses')))
        lp_bugs = self.lp.clean_duplicates(lp_bugs)

        for lbug in lp_bugs:
            synced = any(self.is_bugs_match(lbug, jbug) for jbug in jira_bugs)
            if not synced and not DRY_RUN:
                title = ''
                if lbug['key'] not in lbug['title']:
                    title = self.prefix_title.format(lbug['key'])
                title += lbug['title']

                new_issue = self.jira.create_bug({
                    'title': title,
                    'project_key': self.jira_project,
                    'description': lbug['description'],
                })

                if new_issue:
                    self.jira.update_bug(new_issue.key, {
                        'title': title,
                        'description': lbug['description'],
                        'priority': lbug['priority']['jira'],
                        'status': lbug['status']['jira'],
                    })

    def move_milestones_from_jira(self):
        """Move new milestones from JIRA to Launchpad."""
        pass

    def release_milestone(self):
        """Relise LP milestone."""
        pass


def main():
    log.info('Starting to sync.')

    threads = []
    for project in json.loads(config.get('LP', 'projects')):
        for milestone in json.loads(config.get('LP', 'milestones')):
            th = ThreadSyncBugs(project, milestone, JiraClient(), LpClient())
            th.setDaemon(True)
            threads.append(th)

    for th in threads:
        th.start()

    for th in threads:
        th.join()

    log.info('Successfully synced.')


if __name__ == '__main__':
    main()
