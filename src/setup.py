#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Set up tools.
"""

from email import message_from_string
from pathlib import Path

import setuptools

HERE = Path(__file__).resolve().parent


def read_long_description():
    """
    Read the README from the repository root. It is outside the sdist, so
    when building from the sdist reuse the description stored in PKG-INFO.
    """
    readme = HERE.parent / 'README.md'
    if readme.is_file():
        return readme.read_text(encoding='utf-8')

    pkg_info = HERE / 'PKG-INFO'
    if pkg_info.is_file():
        return message_from_string(
            pkg_info.read_text(encoding='utf-8')
        ).get_payload()

    return ''


setuptools.setup(
    long_description=read_long_description(),
)
