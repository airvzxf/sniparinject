#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Entry script of the executable that PyInstaller builds. An entry script can
not use relative imports, so it imports the installed package.
"""
import sys

from sniparinject.cli import main

sys.exit(main())
