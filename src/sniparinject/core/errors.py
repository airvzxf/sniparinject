#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Errors raised while the game data is parsed.
"""
from struct import error as StructError

from yaml import YAMLError


class GameError(RuntimeError):
    """
    The game data or its settings can not be parsed.

    The first argument is the message and the second one, when it is given,
    is the cascade of classes and functions where the error occurred.
    """


class SettingsError(GameError):
    """
    The settings file is missing, empty or not valid.
    """


# Errors that bad game data or a bad settings file can raise while parsing.
PARSE_ERRORS: tuple[type[Exception], ...] = (
    GameError,
    StructError,
    YAMLError,
    OSError,
    ValueError,
    TypeError,
    LookupError,
    ArithmeticError,
    AttributeError,
)
