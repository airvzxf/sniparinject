#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Unit Test.
"""
from os import utime
from pathlib import Path
from unittest.mock import patch

from mock_open import MockOpen
from pytest import raises
from yaml import dump

from src.sniparinject.core.settings import Settings


class TestSettings:
    def test___init__(self):
        # Arrange
        config_file_expected = 'whatever.txt'
        # Act
        settings = Settings(config_file_expected)
        # Assert
        assert settings.config_file == config_file_expected

    def test_get_dictionary(self):
        with patch('builtins.open', MockOpen()):
            # Arrange
            expected = {'Greetings': {'hello': 'world'}, 'Bye': 'Universe'}
            file_name = '/hck/it/yaml-settings.yml'
            with open(file_name, 'w') as handle:
                yaml_content = dump(expected)
                handle.write(yaml_content)
            with open(file_name, 'r'):
                # Act
                settings = Settings(file_name).get_dictionary()
                # Assert
                assert settings == expected

    def test_get_dictionary_not_file_exists(self):
        # Assert
        with raises(FileNotFoundError):
            # Arrange
            file_name = '/hck/it/invisible.yml'
            # Act
            Settings(file_name).get_dictionary()

    def test_get_dictionary_empty_settings(self):
        with patch('builtins.open', MockOpen()):
            # Arrange
            file_name = '/hck/it/yaml-settings.yml'
            with open(file_name, 'r'):
                try:
                    # Act
                    Settings(file_name).get_dictionary()
                except Exception as error:
                    # Assert
                    error_expected = f'Error: Not found settings in the file `{file_name}`.'
                    assert str(error) == error_expected

    def test_get_dictionary_cached_until_file_changes(self, tmp_path: Path):
        # Arrange
        file_name = tmp_path / 'settings.yml'
        file_name.write_text(dump({'Version': 1}), encoding='utf-8')
        settings = Settings(str(file_name))
        first = settings.get_dictionary()

        # Act
        with patch('src.sniparinject.core.settings.safe_load') as mock_load:
            cached = settings.get_dictionary()

        # Assert
        assert cached is first
        mock_load.assert_not_called()

    def test_get_dictionary_reload_when_file_changes(self, tmp_path: Path):
        # Arrange
        file_name = tmp_path / 'settings.yml'
        file_name.write_text(dump({'Version': 1}), encoding='utf-8')
        settings = Settings(str(file_name))
        assert settings.get_dictionary() == {'Version': 1}
        file_name.write_text(dump({'Version': 2}), encoding='utf-8')
        modified_time = file_name.stat().st_mtime_ns + 1_000_000_000
        utime(file_name, ns=(modified_time, modified_time))

        # Act
        reloaded = settings.get_dictionary()

        # Assert
        assert reloaded == {'Version': 2}
