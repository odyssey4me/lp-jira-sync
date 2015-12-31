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

# TODO(rsalin): export Bug Owner (Issue Reporter) from LP to JIRA
# TODO(rsalin): sync Attachments
# TODO(rsalin): export Comments from LP to JIRA


class Client(object):
    __metaclass__ = ABCMeta

    def __init__(self):
        self.client = self.authenticate()

    @staticmethod
    def get_str(parameter):
        parameter = parameter or ''
        return unicode(parameter)

    @staticmethod
    def get_date(parameter):
        return parser.parse(parameter)

    @abstractmethod
    def authenticate(self):
        pass

    @abstractmethod
    def create_bug(self, fields):
        pass

    @abstractmethod
    def update_bug(self, bug, fields):
        pass


class LpClient(Client):
    lp_api_version = 'devel'

    status_map = {
        'New': 'Open',
        'Incomplete': 'Open',
        'Confirmed': 'Open',
        'Triaged': 'Open',
        'In Progress': 'In Progress',
        'Fix Committed': 'Resolved',
    }

    priority_map = {
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
            log.error("\"%s\" milestone wasn't found on Launchpad. "
                      "Skipped.", milestone_name)
        return bugs

    def process_bug(self, task):
        bug = task.bug
        # owner = None
        # try:
        #     owner = bug.owner.preferred_email_address.email
        #     owner.replace('@mirantis.com', '')
        # except ValueError:
        #     pass

        bug_info = {
            'key': unicode(bug.id),
            'title': bug.title,
            'summary': bug.title,
            'description': self.get_str(bug.description),
            'tags': bug.tags,
            'updated': bug.date_last_updated,
            'bug_target_name': task.bug_target_name,
            'priority': task.importance,
            'status': task.status,
            # 'owner': owner,
            # 'attachments': bug.attachments.entries,
        }
        return bug_info

    def create_bug(self, fields):
        new_bug = None
        title = fields['title']

        log.info('Creating new bug on Launchpad: "%s"', title)
        try:
            new_bug = self.client.bugs.createBug(**fields)
        except Exception as e:
            log.error('Updating bug failed on Launchpad: "%s"', title)
            raise e
        else:
            log.info('Bug was successfully created on Launchpad: "%s"', title)
        return new_bug

    def update_bug(self, bug, fields):
        title = fields.get('title', '')
        description = fields.get('description')
        tags = fields.get('tags')
        status = fields.get('status')
        importance = fields.get('priority')

        log.info('Updating bug on Launchpad: "%s"', title)
        try:
            if title:
                bug.title = title
            if description:
                bug.description = description
            if tags:
                bug.tags = tags
            bug.lp_save()

            # FIXME: find appropriate bug_task
            bug_task = bug.bug_tasks[0]
            if status:
                bug_task.status = status
            if importance:
                bug_task.importance = importance
            bug_task.lp_save()
        except Exception as e:
            log.error('Updating bug failed on Launchpad: "%s"', title)
            raise e
        else:
            log.info('Bug was successfully updated on Launchpad: "%s"', title)


class JiraClient(Client):
    summary_prefix = 'LP Bug #{0}: '

    status_map = {
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

    priority_map = {
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
        bug = {
            'key': unicode(issue.key),
            'title': issue.fields.summary,
            'summary': issue.fields.summary,
            'description': self.get_str(issue.fields.description),
            'tags': issue.fields.labels,
            'priority': issue.fields.priority.name,
            'status': issue.fields.status.name,
            'updated': self.get_date(issue.fields.updated),
        }

        prefix = self.summary_prefix.format(bug['key'])
        if bug['summary'].startswith(prefix):
            bug['summary'] = bug['summary'].replace(prefix, '')
        return bug

    def create_bug(self, fields):
        new_issue = None
        title = fields['summary']

        log.info('Creating new bug on JIRA: "%s"', title)
        try:
            new_issue = self.client.create_issue(fields=fields)
        except JIRAError as e:
            log.error('Creating bug "%s" failed on JIRA: %s (%s)', title)
            raise e
        else:
            log.info('Bug was successfully created on JIRA: "%s"', title)
        return new_issue

    def update_bug(self, bug, fields):
        title = fields.get('summary', '')
        new_status = fields.pop('new_status', None)

        log.info('Updating bug on JIRA: "%s"', title)
        try:
            bug.update(**fields)

            if new_status:
                new_status_id = None
                for tr in self.client.transitions(bug.key):
                    if tr['to']['name'] == new_status:
                        new_status_id = tr['id']

                if new_status_id is not None:
                    self.client.transition_issue(
                        bug.key, new_status_id,
                        comment='Automatically updated by lp_jira_sync '
                                'script.')
        except JIRAError as e:
            log.error('Updating bug "%s" failed on JIRA: %s (%s)', title)
            raise e
        else:
            log.info('Bug was successfully updated on JIRA: "%s"', title)


class ThreadSync(threading.Thread):
    def __init__(self, project, milestone, jira, lp):
        super(ThreadSync, self).__init__()

        self.project = project
        self.milestone = milestone
        self.jira_project = json.loads(
            config.get('JIRA', 'projects')).get(self.project)
        self.jira = jira
        self.lp = lp

    def run(self):
        """Run bugs synchronization."""
        log.info('Syncing for "%s" project, "%s" milestone.',
                 self.project, self.milestone)

        if DRY_RUN:
            log.warn('Dry run mode active. No changes will be performed.')
            log.warn(40 * '-')

        self.sync_created_bugs()
        self.move_bugs_from_lp_to_jira()

    @staticmethod
    def is_bugs_match(lbug, jbug):
        return lbug['title'] in jbug['title'] or lbug['key'] in jbug['title']

    def sync_created_bugs(self):
        """Sync already created tasks."""
        # TODO(rsalin): move bugs to the maintenance milestone.
        # When and how it should be done?
        # TODO(rsalin): update the release date of milestone in LP after
        # the release in JIRA

        jira_bugs = self.jira.get_bugs(self.jira_project, self.milestone)
        lp_bugs = self.lp.get_bugs(
            self.project, self.milestone,
            status=json.loads(config.get('LP', 'sync_statuses')))

        for jbug in jira_bugs:
            for lbug in lp_bugs:
                if not self.is_bugs_match(lbug, jbug):
                    continue

                # TODO update resolvers
                for param in ['summary', 'description', 'tags']:
                    if jbug[param] == lbug[param]:
                        continue

                    # Changed in LP
                    if jbug['updated'] < lbug['updated']:
                        new_title = lbug['title']
                        if lbug['key'] not in jbug['title']:
                            new_title = '{0}{1}'.format(
                                JiraClient.summary_prefix.format(lbug['key']),
                                new_title)

                        priority = LpClient.priority_map[lbug['priority']]
                        status = LpClient.status_map[lbug['status']]

                        fields = {
                            'title': new_title,
                            'tags': lbug['tags'],
                            'description': lbug['description'],
                            'priority': lbug['priority']['jira'],
                            'status': lbug['status']['jira'],
                        }

                        if not DRY_RUN:
                            self.jira.update_bug(self.jira.issue(jbug['key']),
                                                 fields)
                    # Changed in JIRA
                    else:
                        # TODO update bug status, importance, and milestone in LP
                        new_title = jbug['summary']
                        fields = {
                            'title': new_title,
                            'description': jbug['description'],
                            'priority': jbug['priority']['launchpad'],
                            'status': jbug['status']['launchpad'],
                        }

                        if not DRY_RUN:
                            self.lp.update_bug(self.lp.bugs[lbug['key']],
                                               fields)
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
            if not synced:
                title = lbug['title']
                if lbug['key'] not in lbug['title']:
                    title = '{0}{1}'.format(
                        JiraClient.summary_prefix.format(lbug['key']), title)

                tags = lbug['tags']
                tags.append(self.milestone)
                tags.append(lbug['bug_target_name'])

                priority = LpClient.priority_map[lbug['priority']]
                status = LpClient.status_map[lbug['status']]

                fields = {
                    'project': {'key': self.jira_project},
                    'summary': title,
                    'description': lbug['description'],
                    'issuetype': {'name': 'Bug'},
                    'labels': tags,
                    'priority': {'name': priority},
                }
                if not DRY_RUN:
                    new_issue = self.jira.create_bug(fields=fields)
                    if new_issue:
                        self.jira.update_bug(new_issue, fields={
                            'summary': title,
                            'new_status': status,
                        })


def main():
    log.info('Starting to sync.')

    threads = []
    for project in json.loads(config.get('LP', 'projects')):
        for milestone in json.loads(config.get('LP', 'milestones')):
            th = ThreadSync(project, milestone, JiraClient(), LpClient())
            th.setDaemon(True)
            threads.append(th)

    for th in threads:
        th.start()

    for th in threads:
        th.join()

    log.info('Successfully synced.')


if __name__ == '__main__':
    main()
