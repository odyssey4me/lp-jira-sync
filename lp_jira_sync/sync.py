import ConfigParser
from dateutil import parser
import httplib2
import json
import logging
import os
import re
import sys

from jira.client import JIRA
from launchpadlib.launchpad import Launchpad


httplib2.debuglevel = 0

lp_cache_dir = os.path.expanduser(
    os.environ.get('LAUNCHPAD_CACHE_DIR', '~/.launchpadlib/cache'))
lp_creds_filename = os.path.expanduser(
    os.environ.get('LAUNCHPAD_CREDS_FILENAME', '~/.launchpadlib/creds'))
config_filename = os.environ.get('SYNC_CONFIG', 'lp_jira_sync.conf')
sync_dry_run = os.environ.get('SYNC_DRY_RUN', 'False')


def setup_logger():
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s',
                        datefmt="%Y-%m-%d %H:%M:%S",
                        level=logging.DEBUG)
    logging.getLogger("requests").setLevel(logging.ERROR)
    return logging.getLogger('lp_jira_sync')


log = setup_logger()


def get_jira_bugs(url, user, password, project):
    return


def get_launchpad_bugs(project):
    return


def sync_jira_with_launchpad(url, user, password, project, project_key,
                             milestones):
    template = 'Launchpad Bug #{0}: '

    jira_bugs = get_jira_bugs(url, user, password, project)
    launchpad_bugs = get_launchpad_bugs(project)

    # jira = JIRA(basic_auth=(user, password), options={'server': url})
    # launchpad = Launchpad.login_with(project, 'production')

    # TODO: Sync already create tasks
    # TODO: Move new bugs from launchpad to JIRA
    # TODO: Move new milestones from JIRA to launchpad


def main():
    config = ConfigParser.ConfigParser()
    config.read(config_filename)

    log.info('Starting to sync')

    for project in json.loads(config.get('LP', 'projects')):
        log.info('Syncing for {0} project'.format(project))
        sync_jira_with_launchpad(url=config.get('JIRA', 'url'),
                                 user=config.get('JIRA', 'user'),
                                 password=config.get('JIRA', 'password'),
                                 project=project,
                                 project_key=config.get('JIRA', 'project_key'),
                                 milestones=json.loads(
                                     config.get('LP', 'milestones')))
    log.info('Successfully synced')


if __name__ == '__main__':
    main()
