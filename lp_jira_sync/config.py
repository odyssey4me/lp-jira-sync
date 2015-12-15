import ConfigParser
import os


def parse_config():
    config = ConfigParser.ConfigParser()
    filenames = [
        '/etc/lp_jira_sync.conf',
        os.path.join(os.path.expanduser("~"), 'lp_jira_sync.conf'),
        'etc/lp_jira_sync.conf',
    ]
    config.read(filenames)
    return config

settings = parse_config()
