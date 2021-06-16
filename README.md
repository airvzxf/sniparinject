# SniPar Inject

SniPar Inject is the abbreviation of these three word: Sniffer, Parser and
Inject. Intercept and read the network packets to find information about the
game, but it could be useful for any network sniffer. This specific version is
for [PyPi][pypi].

## PyPi

Install the package.

```bash
python3 -m pip install sniparinject
```

### Contributing

Follow the commands to set up and install this package.

```bash
git clone https://github.com/airvzxf/snipar-inject-pypi.git
cd snipar-inject-pypi || exit 123
./script/dev-setup.bash
```

After this setup, it could be easy to activate the vEnv and start to work.

```bash
cd snipar-inject-pypi || exit 123
source ./venv/bin/activate
# Make modification to the source code files (./src/sniparinject).
# Run your changes.
# Create and run the unit tests.
# Finally deactivate the vEnv.
deactivate
```

[pypi]: https://pypi.org/
