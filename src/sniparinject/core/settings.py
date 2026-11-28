#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Given a YAML file it get the settings and return a dictionary with them.
"""
from os import stat
from typing import Any

from yaml import safe_load

# pylint: disable=import-error
from .errors import SettingsError
from .structs import STRUCT_TYPES

PROTOCOLS = ('tcp', 'udp')
OUTPUT_SIZES = ('zero_fill', 'fill', 'fill_left')


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
            settings = safe_load(file)

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


def validate_settings(settings: Any) -> None:
    """
    Check that the settings have the shape the sniffer and the parser need.

    All the problems are collected, so one run shows every mistake in the
    file. Unknown keys are allowed, for example YAML anchors.

    :type settings: Any
    :param settings: The settings read from the YAML file.

    :rtype: None
    :return: Nothing.

    :raises SettingsError: When the settings have one or more problems.
    """
    problems: list[str] = []
    if not isinstance(settings, dict):
        raise SettingsError('The settings must be a mapping.')

    _check_mapping(settings, 'Network', problems, required=False)
    server = _check_mapping(settings, 'Server', problems, required=True)
    protocol = server.get('protocol')
    if protocol is not None and str(protocol).lower() not in PROTOCOLS:
        known = ', '.join(PROTOCOLS)
        problems.append(f'Server.protocol `{protocol}` is not one of {known}.')

    game = _check_mapping(settings, 'Game', problems, required=True)
    if 'Game' in settings and not game.get('host') and not game.get('node'):
        problems.append('Game needs the `host` or the `node` settings.')
    for request in ('host', 'node'):
        side = _check_mapping(game, request, problems, required=False, path='Game')
        actions = _check_mapping(side, 'actions', problems, required=False,
                                 path=f'Game.{request}')
        for packet_id, action in actions.items():
            _check_action(f'Game.{request}.actions.{packet_id}', packet_id, action, problems)

    if problems:
        raise SettingsError('The settings are not valid:\n  - ' + '\n  - '.join(problems))


def _check_mapping(parent: dict, key: str, problems: list[str],
                   required: bool, path: str = '') -> dict:
    """
    Check that a key of the settings is a mapping.

    :type parent: dict
    :param parent: The settings that hold the key.

    :type key: str
    :param key: The key to check.

    :type problems: list[str]
    :param problems: The list where the problems are added.

    :type required: bool
    :param required: Is it a problem when the key is missing?

    :type path: str
    :param path: The location of the parent, for the messages.

    :rtype: dict
    :return: The mapping, or an empty one when it is missing or not valid.
    """
    name = f'{path}.{key}' if path else key
    value = parent.get(key)
    if value is None:
        if required:
            problems.append(f'{name} is missing.')
        return {}

    if not isinstance(value, dict):
        problems.append(f'{name} must be a mapping.')
        return {}

    return value


def _check_action(name: str, packet_id: Any, action: Any, problems: list[str]) -> None:
    """
    Check one action of the settings and its structs.

    :type name: str
    :param name: The location of the action, for the messages.

    :type packet_id: Any
    :param packet_id: The key of the action, which is the packet id.

    :type action: Any
    :param action: The properties of the action.

    :type problems: list[str]
    :param problems: The list where the problems are added.

    :rtype: None
    :return: Nothing.
    """
    if not isinstance(packet_id, int) or isinstance(packet_id, bool):
        problems.append(f'{name}: the packet id must be a number, for example 0x7e.')
    if action is None:
        return
    if not isinstance(action, dict):
        problems.append(f'{name} must be a mapping.')
        return

    structs = action.get('structs')
    if structs is None:
        return
    if not isinstance(structs, list):
        problems.append(f'{name}.structs must be a list.')
        return

    for index, struct in enumerate(structs):
        _check_struct(f'{name}.structs[{index}]', struct, problems)


def _check_struct(name: str, struct: Any, problems: list[str]) -> None:
    """
    Check one struct of an action.

    :type name: str
    :param name: The location of the struct, for the messages.

    :type struct: Any
    :param struct: The properties of the struct.

    :type problems: list[str]
    :param problems: The list where the problems are added.

    :rtype: None
    :return: Nothing.
    """
    if not isinstance(struct, dict):
        problems.append(f'{name} must be a mapping.')
        return

    struct_type = struct.get('type')
    if not isinstance(struct_type, str) or struct_type.lower() not in STRUCT_TYPES:
        problems.append(f'{name}.type `{struct_type}` is not a known struct type.')

    size = struct.get('size')
    if size is not None and not _is_count(size):
        problems.append(f'{name}.size `{size}` must be a number of 0 or more.')

    output = struct.get('output')
    if output is not None and not isinstance(output, dict):
        problems.append(f'{name}.output must be a mapping.')
    elif output:
        for key in OUTPUT_SIZES:
            value = output.get(key)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                problems.append(f'{name}.output.{key} `{value}` must be a number.')

    reference = struct.get('reference')
    if reference is not None and not isinstance(reference, dict):
        problems.append(f'{name}.reference must be a mapping.')


def _is_count(value: Any) -> bool:
    """
    Check that a value is a whole number of 0 or more, as a number or as text.

    :type value: Any
    :param value: The value to check.

    :rtype: bool
    :return: True when the value is a valid count.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, str):
        return value.strip().isdigit()

    return isinstance(value, int) and value >= 0
