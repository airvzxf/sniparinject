#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
The struct types that the settings can use, with their symbol and size.
"""

# Name in the settings -> (symbol of the `struct` module, size in bytes).
STRUCT_TYPES: dict[str, tuple[str, int]] = {
    'char': ('c', 1),
    'signed char': ('b', 1),
    'unsigned char': ('B', 1),
    'bool': ('?', 1),
    'short': ('h', 2),
    'unsigned short': ('H', 2),
    'int': ('i', 4),
    'unsigned int': ('I', 4),
    'long': ('q', 8),
    'unsigned long': ('Q', 8),
    'half precision': ('e', 2),
    'float': ('f', 4),
    'double': ('d', 8),
    'chars': ('s', 1),
}
