#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Given a YAML file it get the settings and return a dictionary with them.
"""
from os import stat

from yaml import load, FullLoader


# pylint: disable=too-few-public-methods
class Settings:
    """
    Parse the configuration file and return the settings.

    The parsed settings are cached by file path and modification time, so
    the file is parsed again only after it changes on disk.
    """

    _cache: dict[str, tuple[int, dict]] = {}

    def __init__(self, config_file: str) -> None:
        """
        Parse the configuration file and return the settings.

        :type config_file: str
        :param config_file: Configuration file in YAML format.

        :rtype: None
        :return: Nothing.
        """
        self.config_file = config_file

    def get_dictionary(self) -> dict:
        """
        Return the settings as a Python's dictionary.

        :rtype: dict
        :return: The settings for Python usage.
        """
        modified_time = self._get_modified_time()
        cached = Settings._cache.get(self.config_file)
        if modified_time is not None and cached and cached[0] == modified_time:
            return cached[1]

        with open(self.config_file, encoding='utf-8') as file:
            settings = load(file, Loader=FullLoader)

        if not settings:
            raise ValueError(f'Error: Not found settings in the file `{self.config_file}`.')

        if modified_time is not None:
            Settings._cache[self.config_file] = (modified_time, settings)

        return settings

    def _get_modified_time(self) -> int | None:
        """
        Return the modification time of the configuration file.

        :rtype: int | None
        :return: The modification time in nanoseconds, or None if it is unknown.
        """
        try:
            return stat(self.config_file).st_mtime_ns
        except OSError:
            return None
