#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Unit Test.
"""
from os import utime
from pathlib import Path
from unittest.mock import patch

from mock_open import MockOpen
from pytest import mark, raises
from yaml import dump

from src.sniparinject.core.errors import SettingsError
from src.sniparinject.core.settings import Settings, validate_settings


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
            with open(file_name):
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
            with open(file_name):
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


def valid_settings() -> dict:
    return {
        'Network': {'interface': 'eth0'},
        'Server': {'ip': '1.2.3.4', 'port': 5122, 'protocol': 'TCP'},
        'Game': {
            'node': {
                'display_message': True,
                'actions': {
                    0x7d: None,
                    0x7e: {'title': 'Tick', 'structs': [
                        {'name': 'Tick', 'type': 'unsigned int',
                         'output': {'type': 'hex', 'auto_zero_fill': True, 'fill': 12}},
                        {'type': 'chars', 'size': '3', 'reference': {1: 'One'}},
                    ]},
                },
            },
            'host': {'actions': {0x80: {'title': 'Header', 'variable_length': True}}},
        },
    }


class TestValidateSettings:
    def test_valid(self):
        # Act / Assert: no error
        validate_settings(valid_settings())

    def test_only_one_side_without_actions(self):
        # Act / Assert: no error
        validate_settings({'Server': {}, 'Game': {'host': {'display_message': False}}})

    def test_not_a_mapping(self):
        with raises(SettingsError) as error:
            validate_settings(['Server'])

        assert error.value.args == ('The settings must be a mapping.',)

    def test_missing_sections(self):
        with raises(SettingsError) as error:
            validate_settings({'Network': 'eth0'})

        assert error.value.args[0] == (
            'The settings are not valid:\n'
            '  - Network must be a mapping.\n'
            '  - Server is missing.\n'
            '  - Game is missing.')

    def test_game_without_sides(self):
        with raises(SettingsError) as error:
            validate_settings({'Server': {}, 'Game': {'other': 1}})

        assert 'Game needs the `host` or the `node` settings.' in error.value.args[0]

    @mark.parametrize('change, problem', [
        (lambda s: s['Server'].update(protocol='icmp'),
         'Server.protocol `icmp` is not one of tcp, udp.'),
        (lambda s: s['Game'].update(node=[1]),
         'Game.node must be a mapping.'),
        (lambda s: s['Game']['node'].update(actions=[1]),
         'Game.node.actions must be a mapping.'),
        (lambda s: s['Game']['node']['actions'].update({'0x7f': None}),
         'Game.node.actions.0x7f: the packet id must be a number, for example 0x7e.'),
        (lambda s: s['Game']['node']['actions'].update({0x7f: 'Tick'}),
         'Game.node.actions.127 must be a mapping.'),
        (lambda s: s['Game']['node']['actions'][0x7e].update(structs={'type': 'int'}),
         'Game.node.actions.126.structs must be a list.'),
        (lambda s: s['Game']['node']['actions'][0x7e]['structs'].append('int'),
         'Game.node.actions.126.structs[2] must be a mapping.'),
        (lambda s: s['Game']['node']['actions'][0x7e]['structs'].append({'type': 'dobule'}),
         'Game.node.actions.126.structs[2].type `dobule` is not a known struct type.'),
        (lambda s: s['Game']['node']['actions'][0x7e]['structs'].append({'name': 'No type'}),
         'Game.node.actions.126.structs[2].type `None` is not a known struct type.'),
        (lambda s: s['Game']['node']['actions'][0x7e]['structs'][1].update(size=-1),
         'Game.node.actions.126.structs[1].size `-1` must be a number of 0 or more.'),
        (lambda s: s['Game']['node']['actions'][0x7e]['structs'][1].update(size='three'),
         'Game.node.actions.126.structs[1].size `three` must be a number of 0 or more.'),
        (lambda s: s['Game']['node']['actions'][0x7e]['structs'][1].update(size=True),
         'Game.node.actions.126.structs[1].size `True` must be a number of 0 or more.'),
        (lambda s: s['Game']['node']['actions'][0x7e]['structs'][0].update(output='hex'),
         'Game.node.actions.126.structs[0].output must be a mapping.'),
        (lambda s: s['Game']['node']['actions'][0x7e]['structs'][0]['output'].update(fill_left='a'),
         'Game.node.actions.126.structs[0].output.fill_left `a` must be a number.'),
        (lambda s: s['Game']['node']['actions'][0x7e]['structs'][1].update(reference=[1]),
         'Game.node.actions.126.structs[1].reference must be a mapping.'),
    ])
    def test_problem(self, change, problem):
        # Arrange
        settings = valid_settings()
        change(settings)

        # Act
        with raises(SettingsError) as error:
            validate_settings(settings)

        # Assert
        assert error.value.args[0] == f'The settings are not valid:\n  - {problem}'
