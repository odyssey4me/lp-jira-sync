import logging

import click

from lp_jira_sync.cmd import sync_bugs
from lp_jira_sync.cmd import sync_milestones

log = logging.getLogger(__name__)


@click.group()
def cli():
    pass


@cli.command('bugs')
def exec_sync_bugs():
    sync_bugs.run()


@cli.command('milestones')
def exec_sync_milestones():
    sync_milestones.run()


def main():
    # TODO(rsalin): load settings
    cli()

if __name__ == '__main__':
    main()
