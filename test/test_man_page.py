#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Unit Test: the man page of the settings matches the code.
"""
import re
from pathlib import Path

from pytest import mark

from src.sniparinject.core.settings import OUTPUT_SIZES, PROTOCOLS
from src.sniparinject.core.structs import STRUCT_TYPES

MAN_PAGE = Path(__file__).resolve().parent.parent / 'src' / 'man' / 'sniparinject-settings.5'
SETTINGS_KEYS = (
    'Network', 'interface', 'offline', 'Server', 'protocol', 'ip', 'port', 'Game', 'host',
    'node', 'display_message', 'actions', 'title', 'variable_length', 'structs', 'name',
    'type', 'size', 'reference', 'output', 'auto_zero_fill', *OUTPUT_SIZES,
)


def _struct_table() -> dict[str, tuple[str, int]]:
    text = MAN_PAGE.read_text(encoding='utf-8')
    table = text.split('.TS\n', 1)[1].split('.TE\n', 1)[0]
    rows = table.splitlines()[2:]
    return {name: (symbol, int(size)) for name, symbol, size in (row.split('\t') for row in rows)}


class TestManPage:
    def test_struct_types_table(self):
        # Act
        table = _struct_table()

        # Assert
        assert table == STRUCT_TYPES

    @mark.parametrize('key', SETTINGS_KEYS)
    def test_settings_key_documented(self, key):
        # Arrange
        text = MAN_PAGE.read_text(encoding='utf-8')

        # Act
        in_synopsis = re.search(rf'^\s*(\\-\s+)?{key}:', text, re.MULTILINE) is not None
        described = f'.BI {key}: ' in text or key in ('Network', 'Server', 'Game', 'host', 'node')

        # Assert
        assert in_synopsis and described, key

    def test_protocols_documented(self):
        # Arrange
        text = MAN_PAGE.read_text(encoding='utf-8')

        # Assert
        assert f'.BI protocol: " {" | ".join(PROTOCOLS)}"' in text
