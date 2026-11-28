#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Show the packet lines on the console, filtered by the `Display` settings.
"""
import re
from functools import lru_cache
from logging import getLogger
from pathlib import Path
from typing import Any

# pylint: disable=import-error
from .errors import PARSE_ERRORS
from .settings import Settings

logger = getLogger(__name__)

ANSI_STYLE = re.compile(r'\x1b\[[0-9;]*m')


def show(settings_path: str, message: str) -> None:
    """
    Print a packet message when the `Display` filters let it through.

    The filters and the log file see the message without its colors. Every
    message is written to the log file, also the ones the filters hide, so
    the log can be searched later.

    :type settings_path: str
    :param settings_path: The path of the YAML file with settings.

    :type message: str
    :param message: The packet message, one or more lines with colors.

    :rtype: None
    :return: Nothing.
    """
    display = _get_display_settings(settings_path)
    plain = strip_style(message)

    log_file = display.get('log_file')
    if log_file:
        _write_log(resolve_path(settings_path, str(log_file)), plain)

    if is_shown(plain, display.get('include'), display.get('exclude')):
        print(message)


def strip_style(message: str) -> str:
    """
    Remove the terminal colors and styles from a message.

    :type message: str
    :param message: The message with ANSI style codes.

    :rtype: str
    :return: The plain text of the message.
    """
    return ANSI_STYLE.sub('', message)


def is_shown(text: str, include: Any, exclude: Any) -> bool:
    """
    Check the text against the include and exclude patterns.

    With include patterns, the text must match at least one of them. The
    text must not match any exclude pattern. A pattern matches anywhere in
    the text, as `re.search` does. A pattern that is not a valid regular
    expression is reported and the text is shown.

    :type text: str
    :param text: The plain text of the message.

    :type include: Any
    :param include: The include patterns from the settings, a list or None.

    :type exclude: Any
    :param exclude: The exclude patterns from the settings, a list or None.

    :rtype: bool
    :return: True when the text must be shown.
    """
    try:
        includes = _compile(_as_tuple(include))
        excludes = _compile(_as_tuple(exclude))
    except re.error as error:
        logger.error('Display: the pattern `%s` is not valid: %s', error.pattern, error)
        return True

    if includes and not any(pattern.search(text) for pattern in includes):
        return False

    return not any(pattern.search(text) for pattern in excludes)


def resolve_path(settings_path: str, path: str) -> Path:
    """
    Resolve a path of the settings, relative to the settings file.

    :type settings_path: str
    :param settings_path: The path of the YAML file with settings.

    :type path: str
    :param path: The path from the settings.

    :rtype: Path
    :return: The absolute or the settings relative path.
    """
    file_path = Path(path).expanduser()
    if file_path.is_absolute():
        return file_path

    return Path(settings_path).parent / file_path


def _get_display_settings(settings_path: str) -> dict:
    """
    Return the `Display` settings, or an empty mapping.

    :type settings_path: str
    :param settings_path: The path of the YAML file with settings.

    :rtype: dict
    :return: The `Display` settings.
    """
    try:
        display = Settings(settings_path).get_dictionary().get('Display')
    except PARSE_ERRORS:
        return {}

    return display if isinstance(display, dict) else {}


def _as_tuple(patterns: Any) -> tuple[str, ...]:
    """
    Convert the patterns of the settings to a tuple of text.

    :type patterns: Any
    :param patterns: One pattern, a list of patterns, or None.

    :rtype: tuple[str, ...]
    :return: The patterns.
    """
    if patterns is None:
        return ()
    if isinstance(patterns, list):
        return tuple(str(pattern) for pattern in patterns)

    return (str(patterns),)


@lru_cache(maxsize=64)
def _compile(patterns: tuple[str, ...]) -> tuple[re.Pattern, ...]:
    """
    Compile the patterns once for each list of patterns.

    :type patterns: tuple[str, ...]
    :param patterns: The patterns.

    :rtype: tuple[re.Pattern, ...]
    :return: The compiled patterns.
    """
    return tuple(re.compile(pattern) for pattern in patterns)


def _write_log(path: Path, text: str) -> None:
    """
    Append the text to the log file.

    :type path: Path
    :param path: The log file.

    :type text: str
    :param text: The plain text of the message.

    :rtype: None
    :return: Nothing.
    """
    try:
        with path.open('a', encoding='utf-8') as file:
            file.write(text + '\n')
    except OSError as error:
        logger.error('Display: can not write the log file `%s`: %s', path, error)
