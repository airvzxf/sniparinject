#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Unit Test.
"""
import re
import runpy
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from src.sniparinject import cli
from src.sniparinject.core.errors import SettingsError

SETTINGS = """\
Network:
  offline: capture.pcap

Server:
  ip: 10.0.0.1
  port: 5122

Game:
  node:
    actions:
      0x7d:
        title: Scenario change
  host:
    actions:
      0x80:
        title: NPC Monster Check
        structs:
          - name: ID
            type: unsigned int
            output:
              type: hex
              auto_zero_fill: Yes
"""


def strip_colors(text: str) -> str:
    """Remove the ANSI colors of the output."""
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


class TestCli:
    def test_main_offline_capture(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        client = {'src': '10.0.0.2', 'dst': '10.0.0.1'}
        server = {'src': '10.0.0.1', 'dst': '10.0.0.2'}
        wrpcap(str(tmp_path / 'capture.pcap'), [
            Ether() / IP(**client) / TCP(sport=40000, dport=5122, flags='PA', seq=1) / Raw(b'\x7d\x00'),
            Ether() / IP(**server) / TCP(sport=5122, dport=40000, flags='PA', seq=1) / Raw(b'\x80\x00\x0f\x00\x00\x00'),
        ])
        settings = tmp_path / 'settings.yml'
        settings.write_text(SETTINGS, encoding='utf-8')

        assert cli.main([str(settings)]) == 0

        output = strip_colors(capsys.readouterr().out)
        assert 'Scenario change' in output
        assert 'NPC Monster Check | ID 0x0000000f' in output

    def test_main_missing_settings_file(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        assert cli.main([str(tmp_path / 'missing.yml')]) == 1
        assert capsys.readouterr().err.startswith('sniparinject: ')

    def test_main_bad_yaml(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        settings = tmp_path / 'settings.yml'
        settings.write_text('Server: [', encoding='utf-8')

        assert cli.main([str(settings)]) == 1
        assert capsys.readouterr().err.startswith('sniparinject: ')

    @patch('src.sniparinject.cli.NetworkSniffer')
    def test_main_settings_error(self, mock_sniffer: MagicMock, capsys: pytest.CaptureFixture):
        mock_sniffer.side_effect = SettingsError('The settings are wrong.')

        assert cli.main(['settings.yml']) == 1
        assert capsys.readouterr().err == 'sniparinject: The settings are wrong.\n'

    @patch('src.sniparinject.cli.NetworkSniffer')
    def test_main_keyboard_interrupt(self, mock_sniffer: MagicMock):
        mock_sniffer.return_value.start.side_effect = KeyboardInterrupt

        assert cli.main(['settings.yml']) == 130

    def test_main_without_settings(self, capsys: pytest.CaptureFixture):
        with pytest.raises(SystemExit) as error:
            cli.main([])

        assert error.value.code == 2
        assert 'settings' in capsys.readouterr().err

    @patch('src.sniparinject.cli.version', return_value='9.8.7')
    def test_main_version(self, _mock_version: MagicMock, capsys: pytest.CaptureFixture):
        with pytest.raises(SystemExit) as error:
            cli.main(['--version'])

        assert error.value.code == 0
        assert capsys.readouterr().out == 'sniparinject 9.8.7\n'

    @patch('src.sniparinject.cli.version', side_effect=PackageNotFoundError)
    def test_package_version_unknown(self, _mock_version: MagicMock):
        assert cli.package_version() == 'unknown'

    @patch('src.sniparinject.cli.main', return_value=0)
    def test_run_module(self, mock_main: MagicMock):
        with pytest.raises(SystemExit) as error:
            runpy.run_module('src.sniparinject', run_name='__main__')

        assert error.value.code == 0
        mock_main.assert_called_once_with()
