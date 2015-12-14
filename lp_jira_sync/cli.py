import logging
import sys

import click

from lp_jira_sync.cmd import sync_bugs

log = logging.getLogger(__name__)


def configure_logging():
    logging_format = ("[%(asctime)s] - %(name)s - %(levelname)s - "
                      "%(message)s")
    logging.basicConfig(stream=sys.stdout,
                        level=logging.DEBUG,
                        format=logging_format)
    logging.getLogger("requests").setLevel(logging.ERROR)


@click.group()
def cli():
    configure_logging()


@cli.command('sync-bugs')
def exec_sync_bugs():
    sync_bugs.run()


if __name__ == '__main__':
    sys.exit(cli())
