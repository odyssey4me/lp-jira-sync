import logging

from lp_jira_sync.config import settings
from lp_jira_sync.db import db
from lp_jira_sync import jira_client
from lp_jira_sync import launchpad_client

log = logging.getLogger(__name__)


def run():
    log.info("Starting to synchronize")

    log.info("Finished syncronizing")
