#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  The `lp_client` module.

  It intended to provide an abstract class `LpClient` that implements generic
  interface for various custom scripts working with a Launchpad bugs.

  The interface takes responsibility on config parsing, ENV variables search,
  implements basic getters for internal variables and provides an easy way
  to iterate ower specified list of projects with a custom handlers
  that should be implemented in a subclasses.
"""

import abc
import ConfigParser
import logging
import os
import sys

from launchpadlib.launchpad import Launchpad


# pylint: disable=E1101
class LpClient(object):
    """Abstract class that implements interface for data manipulation on LP.

    Can't be used directly as some methods should be implemented by subclasses.
    Provides the possibility to iterate over project list, aware of maximum
    limits and so on.
    """
    __metaclass__ = abc.ABCMeta

    # generic default values
    CACHE_DIR = '/tmp/.launchpadlib/cache/'
    LP_API_VERSION = '1.0'  # it also could be 'devel', but it less stable
    RUN_MODE = 'production'  # staging
    DEFAULT_MAXIMUM = -1  # unlimited

    SCRIPT_NAME = 'lp_client'
    CREDENTIALS_FILE = SCRIPT_NAME + '_credentials.conf'
    DEFAULT_CONFIG_FILE = '/etc/custom_scripts/' + SCRIPT_NAME + '.conf'
    ENV_VAR_PREFIX = 'LP'

    def __init__(self, debug, cli_args):
        """LPMilestoneStatusChanger constuctor."""
        self._setup_logger(debug)

        options_dct = self._parse_cli_args(cli_args)

        self.debug = debug
        self.bugs_statistics = {}
        self.processed_issues = 0

        self.config = self._make_config(options_dct)

        self._setup_options(options_dct, self.config)

        self.lp_client = self.__class__.authenticate_client()

    # public methods section
    def process(self):
        """Start migration processing.

        Iterate over all passed projects and process each of them if limit is
        not exceeded.
        """
        for project_name in self.get_projects():
            if self.is_limit_achived():
                break

            self.process_project(project_name)

        logging.info('Migration complete!')
        self.__class__.report_statistics(self.get_stats())

    def get_lp_client(self):
        """Launchpad API client getter."""
        return self.lp_client

    def get_projects(self):
        """Projects to process getter."""
        return self.projects

    def get_stats(self):
        """Return statistics about data being processed."""
        return self.bugs_statistics

    def get_milestone_names(self):
        """Return the list of milestone names."""
        return self.milestones

    def get_limit(self):
        """Return the maximum amount of issues to be processed."""
        return self.maximum

    def get_processed_issues(self):
        """Return the current amount of processed issues."""
        return self.processed_issues

    def increase_proccessed_issues(self):
        """Increase the amount of processed issues and return its value."""
        self.processed_issues += 1
        return self.processed_issues

    def is_limit_achived(self):
        """Return is the total amount of processed issues is over the max."""
        more_than_limit = self.get_processed_issues() >= self.get_limit()
        return (
            more_than_limit and self.get_limit() != -1
        )

    def is_debug(self):
        """Return is the current run mode is debug or not."""
        return self.debug

    # special methods that shoulb be implemented by ancestors
    @abc.abstractmethod
    def process_project(self, project_name):
        """Custom handler for each project to be processed."""

    @abc.abstractmethod
    def process_milestone_on_project(self, project, milestone_name):
        """Custom handler for each milestone to be processed."""

    @staticmethod
    @abc.abstractmethod
    def required_options():
        """Return a list with str names of options required for execution."""

    def _get_env_prefix(self):
        """Return prefix for all ENV related variables."""
        return self.ENV_VAR_PREFIX

    def _get_default_maximum(self):
        """Return default value for max threshold of issues to be processed."""
        return self.DEFAULT_MAXIMUM

    # private methods section, used internally only
    def _setup_logger(self, debug=True):
        """Setup format and debug level for logger output."""
        level = logging.DEBUG if debug else logging.INFO

        logging.basicConfig(
            level=level,
            format='[%(asctime)s] --%(levelname)s-- %(message)s'
        )

        self.logging = logging

        return self.logging

    def _parse_cli_args(self, ap_obj):
        """Parser for ArgumentParser instance object.

        Return a dict of options required for script execution."""
        keys_list = self.__class__.required_options()[:]

        return {key: getattr(ap_obj, key) for key in keys_list}

    def _parse_option(self, option):
        """Parse option value as a string or as a list."""
        if ',' in option:
            return self.__class__.parse_string_list(option)

        return option.strip()

    def _setup_options(self, options_dct, config=None):
        """Setup options required for script execution.

        Running option is taking precedence, after we check ENV variables,
        with fallback to config.
        """
        prefix = self._get_env_prefix()

        for key in self.__class__.required_options():
            if not options_dct.get(key, None):
                env_var_name = prefix + '_' + key.upper()

                if os.getenv(env_var_name, None):
                    setattr(
                        self, key, self._parse_option(os.getenv(env_var_name))
                    )
                elif key in config:
                    setattr(self, key, self._parse_option(config[key]))
                else:
                    if key == 'maximum':
                        setattr(self, key, self._get_default_maximum())
                    else:
                        logging.error(key.capitalize + " wasn't specified.")
                        exit(1)

                if key == 'maximum':
                    try:
                        self.maximum = int(self.maximum)
                    except ValueError:
                        logging.error(
                            'Total amount of issues should be a number.'
                        )
                        exit(1)
            else:
                setattr(self, key, options_dct.get(key))

    def _make_config(self, options_dct):
        """Get config based on script execution mode."""
        opts = self.__class__.required_options()
        if any((options_dct[key] for key in opts)):
            # at least one option was set, assume manual run
            # with config or not
            if options_dct.get('config_file', None):
                # missed options would be retrieved from config passed,
                # not default
                config = self.__class__.config_parser(
                    options_dct.get('config_file')
                )['main']
            else:
                # assume all required options was set
                config = {}
        else:
            # no options was set, assume automatic run with default config path
            config = self.__class__.config_parser()['main']

        return config

    @classmethod
    def authenticate_client(cls):
        """Authenticate on Launchpad and save credentials."""
        logging.info('Launchpad API client authentication..')

        try:
            launchpad = Launchpad.login_with(
                application_name=cls.SCRIPT_NAME,
                service_root=cls.RUN_MODE,
                launchpadlib_dir=cls.CACHE_DIR,
                credentials_file=cls.CREDENTIALS_FILE,
                version=cls.LP_API_VERSION
            )
        except Exception as exc:  # pylint: disable=W0703
            logging.error("Can't login to Launchpad or server is down.")
            raise exc

        return launchpad

    @staticmethod
    def bug_milestone_name(bug):
        """Bug milestone name or empty str if bug has no target milestone."""
        milestone = bug.milestone
        return milestone.name if milestone else ''

    @staticmethod
    def parse_string_list(string_list):
        """Parse config or ENV string lists into Python lists."""
        return [item.strip() for item in string_list.split(',') if item]

    @staticmethod
    def config_parser(config_file=DEFAULT_CONFIG_FILE):
        """Parse the config file."""
        if os.path.exists(config_file):
            config = ConfigParser.ConfigParser()
            config.read(config_file)
            data = {}

            for section in config.sections():
                opts = config.options(section)
                data[section] = {
                    option: config.get(section, option) for option in opts
                }

            return data
        else:
            logging.error("Couldn't find a config file at '%s'", config_file)
            sys.exit(1)

    @staticmethod
    def report_statistics(bugs_statistics):
        """Print statistics about data being processed."""
        for project_name in bugs_statistics:
            for milestone_name in bugs_statistics[project_name]:
                bugs_info = bugs_statistics[project_name][milestone_name]

                logging.info(
                    'project: %s | milestone: %s | '
                    'bugs before: %s | (bugs + subtasks) processed: %s',
                    project_name,
                    milestone_name,
                    bugs_info['total'],
                    bugs_info['migrated']
                )
