import os

from six.moves import configparser


def parse_config():
    config = configparser.SafeConfigParser()
    filenames = [
        '/etc/lp_jira_sync.conf',
        os.path.join(os.path.expanduser("~"), 'lp_jira_sync.conf'),
        'etc/lp_jira_sync.conf',
    ]
    config.read(filenames)
    return config.defaults()

settings = parse_config()
