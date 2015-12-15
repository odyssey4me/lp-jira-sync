import ConfigParser
import logging
import os
import sys


def configure_logging():
    logging_format = ("[%(asctime)s] - %(name)s - %(levelname)s - "
                      "%(message)s")
    logging.basicConfig(stream=sys.stdout,
                        level=logging.DEBUG,
                        format=logging_format)
    logging.getLogger("requests").setLevel(logging.ERROR)


def _parse_config():
    config = ConfigParser.ConfigParser()
    filenames = [
        '/etc/lp_jira_sync.conf',
        os.path.join(os.path.expanduser("~"), 'lp_jira_sync.conf'),
        'etc/lp_jira_sync.conf',
    ]
    config.read(filenames)
    return config


settings = _parse_config()
