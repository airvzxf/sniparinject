#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Unit Test.
"""
from unittest.mock import MagicMock, call, patch

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from src.sniparinject.core.errors import SettingsError
from src.sniparinject.network_sniffer import NetworkSniffer


@pytest.fixture(autouse=True)
def mock_validate_settings():
    """The settings of these tests are partial, they are checked in test_settings."""
    with patch('src.sniparinject.network_sniffer.validate_settings') as mock:
        yield mock


class TestNetworkSniffer:
    style_error = '\x1b[00;37;41m'
    style_end = '\x1b[0m'

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    def test___init___validates_settings(self, mock_settings: MagicMock,
                                         mock_validate_settings: MagicMock):
        # Arrange
        settings = {'Server': {'ip': '1.2.3.4'}}
        mock_settings.return_value = settings
        mock_validate_settings.side_effect = SettingsError('The settings are not valid.')

        # Act
        with pytest.raises(SettingsError):
            NetworkSniffer('bad-settings.yml')

        # Assert
        mock_validate_settings.assert_called_once_with(settings)

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    def test___init__(self, mock_settings: MagicMock):
        # Arrange
        expected_settings_path = 'my-non-settings.yml'
        expected_interface = 'Iceberg'
        expected_ip = 'Server to me'
        expected_port = '12345'
        mock_settings.return_value = {
            'Network': {'interface': expected_interface},
            'Server': {'ip': expected_ip, 'port': expected_port},
        }

        # Act
        network_sniffer = NetworkSniffer(expected_settings_path)

        # Assert
        assert network_sniffer.settings_path == expected_settings_path
        assert network_sniffer.interface == expected_interface
        assert network_sniffer.host_ip == expected_ip
        assert network_sniffer.host_port == int(expected_port)

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.sniff')
    def test_start(self, mock_sniff: MagicMock, mock_settings: MagicMock):
        # Arrange
        expected_interface = 'Touch me'
        expected_protocol = 'Proctors'
        expected_ip = 'Hosting'
        expected_port = '9990'
        mock_settings.return_value = {
            'Network': {'interface': expected_interface},
            'Server': {
                'protocol': expected_protocol,
                'ip': expected_ip,
                'port': expected_port
            },
        }

        # Act
        network_sniffer = NetworkSniffer('any-settings.yml')
        network_sniffer.start()

        # Assert
        mock_sniff.assert_called_once_with(
            iface=expected_interface,
            filter=f'{expected_protocol.lower()} and host {expected_ip} and port {expected_port}',
            count=0,
            store=False,
            prn=network_sniffer._sniff_data
        )

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.sniff')
    def test_start_only_protocol(self, mock_sniff: MagicMock, mock_settings: MagicMock):
        # Arrange
        expected_interface = 'GUI'
        expected_protocol = 'hologram'
        mock_settings.return_value = {
            'Network': {'interface': expected_interface},
            'Server': {
                'protocol': expected_protocol,
            },
        }

        # Act
        network_sniffer = NetworkSniffer('any-settings.yml')
        network_sniffer.start()

        # Assert
        mock_sniff.assert_called_once_with(
            iface=expected_interface,
            filter=f'{expected_protocol.lower()}',
            count=0,
            store=False,
            prn=network_sniffer._sniff_data
        )

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.sniff')
    def test_start_only_host_port(self, mock_sniff: MagicMock, mock_settings: MagicMock):
        # Arrange
        expected_interface = 'GUI'
        expected_protocol = 'hologram'
        expected_host_port = '6854'
        mock_settings.return_value = {
            'Network': {'interface': expected_interface},
            'Server': {
                'protocol': expected_protocol,
                'port': expected_host_port,
            },
        }

        # Act
        network_sniffer = NetworkSniffer('any-settings.yml')
        network_sniffer.start()

        # Assert
        mock_sniff.assert_called_once_with(
            iface=expected_interface,
            filter=f'{expected_protocol.lower()} and port {expected_host_port}',
            count=0,
            store=False,
            prn=network_sniffer._sniff_data
        )

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.sniff')
    def test_start_only_host_ip(self, mock_sniff: MagicMock, mock_settings: MagicMock):
        # Arrange
        expected_interface = 'GUI'
        expected_protocol = 'hologram'
        expected_host_ip = '1285.15.248.1'
        mock_settings.return_value = {
            'Network': {'interface': expected_interface},
            'Server': {
                'protocol': expected_protocol,
                'ip': expected_host_ip,
            },
        }

        # Act
        network_sniffer = NetworkSniffer('any-settings.yml')
        network_sniffer.start()

        # Assert
        mock_sniff.assert_called_once_with(
            iface=expected_interface,
            filter=f'{expected_protocol.lower()} and host {expected_host_ip}',
            count=0,
            store=False,
            prn=network_sniffer._sniff_data
        )

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.Game')
    def test__sniff_data_request_without_data(self, mock_game: MagicMock, mock_settings: MagicMock):
        # Arrange
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'ip': '123', 'port': 5},
        }

        # Act
        network_sniffer = NetworkSniffer('')
        network_sniffer._sniff_data(TCP() / IP())

        # Assert
        mock_game.assert_not_called()

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.Game')
    def test__sniff_data_request_without_tcp(self, mock_game: MagicMock, mock_settings: MagicMock):
        # Arrange
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'ip': '987', 'port': 98},
        }

        # Act
        network_sniffer = NetworkSniffer('')
        network_sniffer._sniff_data(IP() / Raw(b'\xff'))

        # Assert
        mock_game.assert_not_called()

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.Game')
    def test__sniff_data_skip_packet_with_other_protocol(self, mock_game: MagicMock, mock_settings: MagicMock):
        # Arrange
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'protocol': 'udp', 'ip': '12.218.12.2', 'port': 541},
        }

        # Act
        network_sniffer = NetworkSniffer('')
        network_sniffer._sniff_data(IP() / TCP(flags='PA') / Raw(b'\xff'))

        # Assert
        mock_game.assert_not_called()

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.Game')
    def test__sniff_data_class_game(self, mock_game: MagicMock, mock_settings: MagicMock):
        # Arrange
        expected_settings_path = 'hello-from-the-other-side.yml'
        expected_host = False
        expected_packet: Ether = TCP(flags='PA') / IP() / Raw(b'\x00\x01\x02')
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'ip': 'goliath.com', 'port': 987},
        }

        mock_game.complete_length.side_effect = lambda _path, _host, data: len(data)

        # Act
        network_sniffer = NetworkSniffer(expected_settings_path)
        network_sniffer._sniff_data(expected_packet)

        # Assert
        mock_game.assert_called_once_with(
            expected_settings_path, expected_host, b'\x00\x01\x02')

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.Game')
    def test__sniff_data_host_true_when_only_has_port(self, mock_game: MagicMock, mock_settings: MagicMock):
        # Arrange
        expected_settings_path = 'hello-from-the-other-side.yml'
        expected_host = True
        host_port = 987
        expected_packet: Ether = TCP(sport=host_port, flags='PA') / IP() / Raw(b'\x00\x01\x02')
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'port': host_port},
        }

        mock_game.complete_length.side_effect = lambda _path, _host, data: len(data)

        # Act
        network_sniffer = NetworkSniffer(expected_settings_path)
        network_sniffer._sniff_data(expected_packet)

        # Assert
        mock_game.assert_called_once_with(
            expected_settings_path, expected_host, b'\x00\x01\x02')

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.Game')
    def test__sniff_data_host_true_when_only_has_ip(self, mock_game: MagicMock, mock_settings: MagicMock):
        # Arrange
        expected_settings_path = 'hello-from-the-other-side.yml'
        expected_host = True
        host_ip = '2.21.25.218'
        expected_packet: Ether = TCP(flags='PA') / IP(src=host_ip) / Raw(b'\x00\x01\x02')
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'ip': host_ip},
        }

        mock_game.complete_length.side_effect = lambda _path, _host, data: len(data)

        # Act
        network_sniffer = NetworkSniffer(expected_settings_path)
        network_sniffer._sniff_data(expected_packet)

        # Assert
        mock_game.assert_called_once_with(
            expected_settings_path, expected_host, b'\x00\x01\x02')

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.Game')
    def test__sniff_data_with_udp_protocol(self, mock_game: MagicMock, mock_settings: MagicMock):
        # Arrange
        expected_settings_path = 'hello-from-the-other-side.yml'
        expected_host = True
        host_ip = '2.21.25.218'
        host_port = 5153
        expected_packet: Ether = UDP(sport=host_port) / IP(src=host_ip) / Raw(b'\x00\x01\x02')
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'protocol': 'udp', 'ip': host_ip, 'port': host_port},
        }

        # Act
        network_sniffer = NetworkSniffer(expected_settings_path)
        network_sniffer._sniff_data(expected_packet)

        # Assert
        mock_game.assert_called_once_with(
            expected_settings_path, expected_host, expected_packet)

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.Game')
    def test__sniff_data_skip_packet_without_ip_layer(self, mock_game: MagicMock, mock_settings: MagicMock):
        # Arrange
        expected_packet: Ether = UDP() / Raw()
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'protocol': 'udp', 'ip': '12.218.12.2', 'port': 541},
        }

        # Act
        network_sniffer = NetworkSniffer('')
        network_sniffer._sniff_data(expected_packet)

        # Assert
        mock_game.assert_not_called()

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.sniff')
    def test_start_offline(self, mock_sniff: MagicMock, mock_settings: MagicMock):
        # Arrange
        mock_settings.return_value = {
            'Network': {'interface': 'eth0', 'offline': 'capture.pcap'},
            'Server': {'ip': '1.2.3.4', 'port': 5122},
        }

        # Act
        network_sniffer = NetworkSniffer('/the/game/settings.yml')
        network_sniffer.start()

        # Assert
        assert network_sniffer.offline == '/the/game/capture.pcap'
        mock_sniff.assert_called_once_with(
            offline='/the/game/capture.pcap',
            count=0,
            store=False,
            prn=network_sniffer._sniff_data
        )

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    def test___init___offline_absolute_path(self, mock_settings: MagicMock):
        # Arrange
        mock_settings.return_value = {
            'Network': {'offline': '/captures/game.pcapng'},
            'Server': {'port': 5122},
        }

        # Act
        network_sniffer = NetworkSniffer('settings.yml')

        # Assert
        assert network_sniffer.offline == '/captures/game.pcapng'
        assert network_sniffer.interface is None

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.Game')
    def test__sniff_data_offline_server_packets(self, mock_game: MagicMock, mock_settings: MagicMock):
        # Arrange
        host_ip = '52.174.196.146'
        host_port = 5122
        from_host: Ether = IP(src=host_ip, dst='10.0.0.2') / TCP(sport=host_port, dport=40000, flags='PA') / Raw(b'\x01')
        from_node: Ether = IP(src='10.0.0.2', dst=host_ip) / TCP(sport=40000, dport=host_port, flags='PA') / Raw(b'\x02')
        mock_settings.return_value = {
            'Network': {'offline': 'capture.pcap'},
            'Server': {'ip': host_ip, 'port': host_port},
        }

        mock_game.complete_length.side_effect = lambda _path, _host, data: len(data)

        # Act
        network_sniffer = NetworkSniffer('settings.yml')
        network_sniffer._sniff_data(from_host)
        network_sniffer._sniff_data(from_node)

        # Assert
        assert mock_game.call_args_list == [
            call('settings.yml', True, b'\x01'),
            call('settings.yml', False, b'\x02'),
        ]

    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    @patch('src.sniparinject.network_sniffer.Game')
    def test__sniff_data_offline_skip_other_packets(self, mock_game: MagicMock, mock_settings: MagicMock):
        # Arrange
        other_ip: Ether = IP(src='8.8.8.8', dst='10.0.0.2') / TCP(sport=5122, dport=40000, flags='PA') / Raw(b'\x01')
        other_port: Ether = IP(src='52.174.196.146', dst='10.0.0.2') / TCP(sport=6901, dport=40000, flags='PA') / Raw(b'\x01')
        mock_settings.return_value = {
            'Network': {'offline': 'capture.pcap'},
            'Server': {'ip': '52.174.196.146', 'port': 5122},
        }

        # Act
        network_sniffer = NetworkSniffer('settings.yml')
        network_sniffer._sniff_data(other_ip)
        network_sniffer._sniff_data(other_port)

        # Assert
        mock_game.assert_not_called()

    @patch('src.sniparinject.network_sniffer.Game.start', autospec=True)
    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    def test__sniff_data_reassemble_tcp_segments(self, mock_settings: MagicMock, mock_start: MagicMock):
        # Arrange
        host_ip = '52.174.196.146'
        host_port = 5122
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'ip': host_ip, 'port': host_port},
            'Game': {'host': {'actions': {
                1: {'structs': [{'type': 'int'}]},
                0x8000: {'variable_length': True},
            }}},
        }
        received = []
        mock_start.side_effect = lambda game: received.append(game.raw_data)

        def segment(sequence: int, payload: bytes) -> Ether:
            return IP(src=host_ip, dst='10.0.0.2') / TCP(
                sport=host_port, dport=40000, seq=sequence, flags='PA') / Raw(payload)

        # Act
        network_sniffer = NetworkSniffer('settings.yml')
        network_sniffer._sniff_data(segment(10, b'\x01\x00\x01\x02\x03\x04\x01\x00\x05'))
        network_sniffer._sniff_data(segment(10, b'\x01\x00\x01\x02\x03\x04\x01\x00\x05'))
        network_sniffer._sniff_data(segment(19, b'\x06'))
        network_sniffer._sniff_data(segment(20, b'\x07\x08\x00\x80'))
        network_sniffer._sniff_data(segment(24, b'\x05\x00\xff'))

        # Assert
        assert received == [
            b'\x01\x00\x01\x02\x03\x04',
            b'\x01\x00\x05\x06\x07\x08',
            b'\x00\x80\x05\x00\xff',
        ]

    @patch('src.sniparinject.network_sniffer.Game.start', autospec=True)
    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    def test__sniff_data_syn_starts_new_stream(self, mock_settings: MagicMock, mock_start: MagicMock):
        # Arrange
        host_ip = '52.174.196.146'
        host_port = 5122
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'ip': host_ip, 'port': host_port},
            'Game': {'host': {'actions': {
                1: {'structs': [{'type': 'int'}]},
            }}},
        }
        received = []
        mock_start.side_effect = lambda game: received.append(game.raw_data)

        def segment(sequence: int, flags: str, payload: bytes = b'') -> Ether:
            packet = IP(src=host_ip, dst='10.0.0.2') / TCP(
                sport=host_port, dport=40000, seq=sequence, flags=flags)
            return packet / Raw(payload) if payload else packet

        # Act
        network_sniffer = NetworkSniffer('settings.yml')
        network_sniffer._sniff_data(segment(1000, 'PA', b'\x01\x00\x01\x02\x03\x04'))
        network_sniffer._sniff_data(segment(499, 'SA'))
        network_sniffer._sniff_data(segment(504, 'PA', b'\x03\x04'))
        network_sniffer._sniff_data(segment(500, 'PA', b'\x01\x00\x01\x02'))

        # Assert
        assert received == [
            b'\x01\x00\x01\x02\x03\x04',
            b'\x01\x00\x01\x02\x03\x04',
        ]

    @patch('src.sniparinject.network_sniffer.Game.start', autospec=True)
    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    def test__sniff_data_retransmitted_syn_keeps_stream(self, mock_settings: MagicMock, mock_start: MagicMock):
        # Arrange
        host_ip = '52.174.196.146'
        host_port = 5122
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'ip': host_ip, 'port': host_port},
            'Game': {'host': {'actions': {
                1: {'structs': [{'type': 'int'}]},
            }}},
        }
        received = []
        mock_start.side_effect = lambda game: received.append(game.raw_data)

        def segment(sequence: int, flags: str, payload: bytes = b'') -> Ether:
            packet = IP(src=host_ip, dst='10.0.0.2') / TCP(
                sport=host_port, dport=40000, seq=sequence, flags=flags)
            return packet / Raw(payload) if payload else packet

        # Act
        network_sniffer = NetworkSniffer('settings.yml')
        network_sniffer._sniff_data(segment(499, 'SA'))
        network_sniffer._sniff_data(segment(500, 'PA', b'\x01\x00\x01\x02'))
        network_sniffer._sniff_data(segment(499, 'SA'))
        network_sniffer._sniff_data(segment(504, 'PA', b'\x03\x04'))

        # Assert
        assert received == [b'\x01\x00\x01\x02\x03\x04']

    def test__parse_port(self):
        # Arrange
        # Act
        # Assert
        assert NetworkSniffer._parse_port(5122) == 5122
        assert NetworkSniffer._parse_port('5122') == 5122
        assert NetworkSniffer._parse_port(None) is None
        assert NetworkSniffer._parse_port('') is None

    def test__parse_port_not_a_number(self):
        # Arrange
        # Act
        with pytest.raises(ValueError, match='is not a number'):
            NetworkSniffer._parse_port('http')

    def test__parse_port_out_of_range(self):
        # Arrange
        # Act
        with pytest.raises(ValueError, match='between 1 and 65535'):
            NetworkSniffer._parse_port(65536)

    @patch('src.sniparinject.network_sniffer.Game.start', autospec=True)
    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    def test__sniff_data_fin_and_rst_close_stream(self, mock_settings: MagicMock, mock_start: MagicMock):
        # Arrange
        host_ip = '52.174.196.146'
        host_port = 5122
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'ip': host_ip, 'port': host_port},
            'Game': {'host': {'actions': {
                1: {'structs': [{'type': 'int'}]},
            }}},
        }
        received = []
        mock_start.side_effect = lambda game: received.append(game.raw_data)

        def segment(sport: int, sequence: int, flags: str, payload: bytes = b'') -> Ether:
            packet = IP(src=host_ip, dst='10.0.0.2') / TCP(
                sport=sport, dport=40000, seq=sequence, flags=flags)
            return packet / Raw(payload) if payload else packet

        network_sniffer = NetworkSniffer('settings.yml')

        # Act
        network_sniffer._sniff_data(segment(host_port, 100, 'PA', b'\x01\x00\x01\x02\x03\x04'))
        network_sniffer._sniff_data(segment(host_port, 106, 'FA', b'\x01\x00\x01\x02\x03\x04'))
        after_fin = dict(network_sniffer.streams)
        network_sniffer._sniff_data(segment(host_port, 200, 'PA', b'\x01\x00'))
        network_sniffer._sniff_data(segment(host_port, 202, 'R'))
        after_rst = dict(network_sniffer.streams)

        # Assert
        assert received == [b'\x01\x00\x01\x02\x03\x04', b'\x01\x00\x01\x02\x03\x04']
        assert not after_fin
        assert not after_rst

    @patch('src.sniparinject.network_sniffer.Game.start', autospec=True)
    @patch('src.sniparinject.network_sniffer.Settings.get_dictionary')
    def test__sniff_data_fin_keeps_stream_with_gap(self, mock_settings: MagicMock, mock_start: MagicMock):
        # Arrange
        host_ip = '52.174.196.146'
        host_port = 5122
        mock_settings.return_value = {
            'Network': {'interface': ''},
            'Server': {'ip': host_ip, 'port': host_port},
            'Game': {'host': {'actions': {
                1: {'structs': [{'type': 'int'}]},
            }}},
        }
        received = []
        mock_start.side_effect = lambda game: received.append(game.raw_data)

        def segment(sequence: int, flags: str, payload: bytes = b'') -> Ether:
            packet = IP(src=host_ip, dst='10.0.0.2') / TCP(
                sport=host_port, dport=40000, seq=sequence, flags=flags)
            return packet / Raw(payload) if payload else packet

        network_sniffer = NetworkSniffer('settings.yml')

        # Act
        network_sniffer._sniff_data(segment(100, 'PA', b'\x01\x00'))
        network_sniffer._sniff_data(segment(104, 'PA', b'\x03\x04'))
        network_sniffer._sniff_data(segment(106, 'FA'))
        network_sniffer._sniff_data(segment(102, 'PA', b'\x01\x02'))

        # Assert
        assert received == [b'\x01\x00\x01\x02\x03\x04']
