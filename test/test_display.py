#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Unit Test.
"""
from pathlib import Path
from unittest.mock import MagicMock, patch

from pytest import mark

from src.sniparinject.core.display import is_shown, resolve_path, show, strip_style

COLORED = '\x1b[00;93;44m<-- Being name\x1b[0m\x1b[00;30;44m |\x1b[0m'


def write_settings(tmp_path: Path, display: str) -> str:
    settings = tmp_path / 'settings.yml'
    settings.write_text(f'Server: {{}}\nGame: {{host: {{}}}}\n{display}', encoding='utf-8')
    return str(settings)


class TestDisplay:
    def test_strip_style(self):
        assert strip_style(COLORED) == '<-- Being name |'

    @mark.parametrize('include, exclude, expected', [
        (None, None, True),
        ([], [], True),
        (['Being'], None, True),
        (['Tick', 'Being'], None, True),
        (['Tick'], None, False),
        ('^<-- ', None, True),
        (None, ['name'], False),
        (['Being'], ['name'], False),
        (None, ['Tick'], True),
    ])
    def test_is_shown(self, include, exclude, expected):
        assert is_shown('<-- Being name |', include, exclude) is expected

    @patch('src.sniparinject.core.display.logger')
    def test_is_shown_bad_pattern(self, mock_logger: MagicMock):
        assert is_shown('<-- Being name |', ['('], None) is True
        mock_logger.error.assert_called_once()

    def test_resolve_path(self):
        assert resolve_path('/a/settings.yml', 'out.log') == Path('/a/out.log')
        assert resolve_path('/a/settings.yml', '/b/out.log') == Path('/b/out.log')

    @patch('builtins.print')
    def test_show_without_settings(self, mock_print: MagicMock):
        show('/not/a/file.yml', COLORED)
        mock_print.assert_called_once_with(COLORED)

    @patch('builtins.print')
    def test_show_filtered_and_logged(self, mock_print: MagicMock, tmp_path: Path):
        settings = write_settings(tmp_path, 'Display:\n  exclude: [Tick]\n  log_file: out.log\n')

        show(settings, COLORED)
        show(settings, '--> Tick |')

        mock_print.assert_called_once_with(COLORED)
        assert (tmp_path / 'out.log').read_text(encoding='utf-8') == '<-- Being name |\n--> Tick |\n'

    @patch('src.sniparinject.core.display.logger')
    @patch('builtins.print')
    def test_show_log_error(self, mock_print: MagicMock, mock_logger: MagicMock, tmp_path: Path):
        settings = write_settings(tmp_path, 'Display:\n  log_file: missing/out.log\n')

        show(settings, COLORED)

        mock_print.assert_called_once_with(COLORED)
        mock_logger.error.assert_called_once()
