#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Command line of SniParInject: sniff the packets described by a settings file.
"""
import argparse
import sys
from importlib.metadata import PackageNotFoundError, version

import yaml

from .core.errors import GameError
from .network_sniffer import NetworkSniffer


def package_version() -> str:
    """
    Get the installed version of the package.

    :rtype: str
    :return: The version, or `unknown` when the package metadata is missing.
    """
    try:
        return version('sniparinject')
    except PackageNotFoundError:
        return 'unknown'


def build_parser() -> argparse.ArgumentParser:
    """
    Build the parser of the command line arguments.

    :rtype: argparse.ArgumentParser
    :return: The parser.
    """
    parser = argparse.ArgumentParser(
        prog='sniparinject',
        description='Sniff the network packets of a game and print them as '
                    'the settings file describes. Sniffing a network '
                    'interface needs root permissions; reading a capture '
                    'file (Network.offline) does not.',
        epilog='The settings keys are described in sniparinject-settings(5).',
    )
    parser.add_argument('settings', help='the YAML settings file')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {package_version()}')
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    Run the sniffer with the settings file given in the arguments.

    :type argv: list[str] | None
    :param argv: The arguments, without the program name. None reads sys.argv.

    :rtype: int
    :return: The exit status: 0 on success, 1 on an error, 130 on Ctrl+C.
    """
    arguments = build_parser().parse_args(argv)
    try:
        NetworkSniffer(arguments.settings).start()
    except KeyboardInterrupt:
        return 130
    except (GameError, OSError, ValueError, yaml.YAMLError) as error:
        print(f'sniparinject: {error}', file=sys.stderr)
        return 1
    return 0
