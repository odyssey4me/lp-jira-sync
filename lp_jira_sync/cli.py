import sys

import click

from config import settings
from lp_jira_sync.cmd import sync_bugs


@click.group()
def cli():
    settings.configure_logging()


@cli.command('sync-bugs')
def exec_sync_bugs():
    sync_bugs.run()


if __name__ == '__main__':
    sys.exit(cli())
