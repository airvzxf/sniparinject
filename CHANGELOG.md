# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-11-28

### Added

- Check the settings file when the sniffer starts and list every problem:
  missing `Server` or `Game`, unknown struct type, bad size, text packet
  ids, outputs and references that are not mappings (#47).
- `GameError` and `SettingsError` exceptions. Both are a `RuntimeError`, so
  code that catches `RuntimeError` keeps working (#47).
- CI: mypy, Ruff and Bandit checks, and a release workflow that publishes
  to PyPI with Trusted Publishing (#48).

### Changed

- Parse errors are reported with `logging` (stderr) instead of `print`, so
  they don't mix with the packet lines on stdout (#47).
- Only a fixed list of parse errors is caught, not every `Exception` (#47).
- CI tests Python 3.11, 3.12, 3.13 and 3.14 (latest patch of each) (#48).

### Fixed

- The `double` struct type is 8 bytes, not 6 (#47).

## [1.0.3] - 2026-11-28

### Fixed

- Parse the game packets of a buffer in a loop instead of recursion, which
  raised `RecursionError` for about a thousand packets in one buffer (#45).
- `Server.port` is converted to a number; a port that is not a number or
  not between 1 and 65535 fails at start (#45).
- `display_message`: a missing key shows the messages, any false value
  (`No`, `false`, `0`) hides them (#45).
- Read `settings.yml` with `yaml.safe_load` (#45).
- Forget the TCP stream of a direction after a FIN or RST, unless segments
  still wait for a gap (#45).

## [1.0.2] - 2026-11-27

### Fixed

- A SYN starts a new TCP stream for its direction, so a new connection on
  the same addresses and ports doesn't lose its data (#43).

## [1.0.1] - 2026-11-27

### Fixed

- Keep out-of-order TCP segments until the gap fills, so a late segment no
  longer loses its game packets (#41).

## [1.0.0] - 2026-11-27

- First stable release.

[Unreleased]: https://github.com/airvzxf/sniparinject/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/airvzxf/sniparinject/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/airvzxf/sniparinject/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/airvzxf/sniparinject/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/airvzxf/sniparinject/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/airvzxf/sniparinject/releases/tag/v1.0.0
