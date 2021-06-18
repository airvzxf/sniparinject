#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Set up tools.
"""

import setuptools

with open('../README.md', 'r', encoding='utf-8') as file_handler:
    long_description = file_handler.read()

setuptools.setup(
    long_description=long_description,
)
