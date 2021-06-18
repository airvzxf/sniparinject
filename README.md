# SniParInject

It is the abbreviation of these three word: Sniffer, Parser and Inject.
Intercept and read the network packets to find information about the game, but
it could be useful for any network sniffer purpose. The injection is coming
soon.

This project is work in progress. Reefer to the [To-Do's][todo] list to check
what is done and what is coming.

## Run it

### Locally

For more information go to the [package's page in PyPi][pypi].

Install the package.

```bash
python3 -m pip install sniparinject
```

### As a developer

The only two special Python's packages that you need are `scapy` and
`PyYAML`, the suggested version of `Python` is `>= 3.9`. Follow the commands to
set up and install this package.

```bash
git clone https://github.com/airvzxf/sniparinject.git
cd sniparinject || exit 123
./script/setup-dev.bash
```

After this setup, it could be easy to activate the vEnv and start to work.

```bash
# Inside of the GitHub cloned directory.
source ./venv/bin/activate
cd src/sniparinject || exit 123
# Make modification to the source code files.
# Run your changes.
# Finally deactivate the vEnv.
deactivate
```

## Usage

The most basic setup is creating one Python file, and the settings file.

`main.py`

```python
#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
The most basic example of SniParInject.
"""
from sniparinject.network_sniffer import NetworkSniffer

if __name__ == '__main__':
    SETTINGS_PATH = 'settings.yml'
    NetworkSniffer(SETTINGS_PATH).start()
```

`settings.yml`

```yaml
%YAML 1.1
---
Network:
  interface: enp4s0

Server:
  ip: 52.174.196.146
  port: 5122

Game:
  node:
    actions:
      0x7d:
        title: Scenario change
      0x85:
        title: Player move to
        display_message: Yes
        structs:
          - type: chars
            size: 3
            output:
              type: hex
  host:
    actions:
      0x78:
        title: NPC Info
        structs:
          - name: ID
            type: unsigned int
            output:
              type: hex
              auto_zero_fill: Yes
          - type: chars
            size: 1
            output:
              type: hex
          - name: HP
            type: unsigned short
          - name: Max HP
            type: unsigned short
```

The settings, needs to set the network interface which could get by the
command `ip addr` or `ls -1 /sys/class/net`. The next two are the host IP and
its port, in our case we will use the game IP and port. You could use this
command `lsof -i` to show all the process which has connection to the network,
check the column `NAME` to review the connection
`manaplus   5563 wolf ... MSIGT73EVR7RF:55238->52.174.196.146:5122
(ESTABLISHED)`. Also, another command is
`sudo netstat -nap | grep -i NAME_OF_GAME_PROCESS`.

Execute the application:

```bash
# Execute with root permissions the main script.
sudo python3 main.py
```

### Example

This example is for the game `Mana Plus`.

[![asciicast][ascii-mana-image]][ascii-mana-link]

## Settings

This software **does not need** to **modify** any file in the **source code**.
Create a `settings.yml` file which is able to add, modify or remove any parse
rules.

### Examples

The required fields for the `Server` information are `ip`, `port` or both.

```yaml
Network:
  interface: enp4s0

Server:
  ip: 52.174.196.146
  port: 5122
```

---

The default protocol is `TCP` but you can assign the `UDP`.

```yaml
Network:
  interface: enp4s0

Server:
  protocol: UDP
  port: 6666
```

---

This is the basic structure without any rule.

```yaml
Game:
  node:
  host:
```

---

Example for node, which is the raw data send from your computer to the server.

Here will capture all the packets which start with the id `0x7d` equal to the
raw data `\x00\x7d`. It will print in your console:
`--> Scenario change |` every time your computer send to the server this
packet.

The action `0x85` equal to the raw data `\x00\x85`. It will print in your
console: `--> Player move to | a07f18 |`. Means the player communicate to the
server that it is moving to this position.

```yaml
Game:
  node:
    actions:
      0x7d:
        title: Scenario change
      0x85:
        title: Player move to
        structs:
          - type: chars
            size: 3
            output:
              type: hex
```

---

Same example as above, but we do not want to print the action `Player move to`.
Add `display_message: No` in the action which want to avoid the print.

```yaml
Game:
  node:
    actions:
      0x7d:
        title: Scenario change
      0x85:
        title: Player move to
        display_message: No
        structs:
          - type: chars
            size: 3
            output:
              type: hex
```

---

Same example as above, but we do not want to print any node action, it means
the actions sent by you computer to the server. It will print only the host's
actions. The default value for the node/host or actions is always
`display_message: Yes`, it does need to set explicitly.

```yaml
Game:
  node:
    display_message: No
    actions:
      0x7d:
        title: Scenario change
  host:
    actions:
      0xad:
        title: Scenario change
```

---

What are the structs? It is the way that it will parse the data. Basically,
split the raw data based on the Python Structs which are C Types. They are
well-known as an integer, char, long, float, etc. You will find information in
the official web page [Python Structs][structs]. In the game the function which
contains this logic is
`def _get_struct(self, struct_type: str, repeat_count: int = 1)`
in `./core/game.py`.

```python
# 'ID': ('Python struct symbol', Size in bytes)
structs = {
    'char': ('c', 1),
    'signed char': ('b', 1),
    'unsigned char': ('B', 1),
    'bool': ('?', 1),
    'short': ('h', 2),
    'unsigned short': ('H', 2),
    'int': ('i', 4),
    'unsigned int': ('I', 4),
    'long': ('q', 8),
    'unsigned long': ('Q', 8),
    'half precision': ('e', 2),
    'float': ('f', 4),
    'double': ('d', 6),
    'chars': ('s', 0),
}
```

---

The option `size` returns the number of repeats of this struct. One example is
if the setting's action has `type: int` and `size: 8`, it will returns
`4i` and it is exactly the same to write `iiii`. The example below will
return `5s`.

```yaml
structs:
  - type: chars
    size: 5
```

---

In this example it will take the raw data and split in two. The first is an
`unsigned int` with `4 bytes` of size and the `char` with `1 byte` of size. The
raw data could be `\x00\x80 \x0f\x00\x00\x00 \xf8`, I split intentional with
spaces to be more clear. The rule in the example take the first
`unsigned short` value as an action ID (`\x00\x80` equal to `0x80`), then
extract as a `unsigned int` the monster ID, and the last byte as an unknown.
The output will be `---> NPC Monster Check | ID 0x0000000f | 0xf8 |`. Note in
the monster ID that the raw data, and the output is different:
`\x0f\x00\x00\x00` vs `0x0000000f`. It is because the network data is coming
in `big-endian` and the human / machine-readable for numbers is
in `little-endian`.

```yaml
Game:
  node:
    actions:
      0x80:
        title: NPC Monster Check
        structs:
          - name: ID
            type: unsigned int
            output:
              type: hex
              auto_zero_fill: Yes
          - type: chars
            size: 1
            output:
              type: hex
```

---

In every struct there is an option to add the name which will display before
the value. In the follow example the first struct does not have the name, and
the second has the name id. The output will be
`---> NPC Monster Check | 56 | ID 78 |`.

```yaml
Game:
  node:
    actions:
      0x80:
        title: NPC Monster Check
        structs:
          - type: unsigned int
          - name: ID
            type: unsigned int
```

---

What happen if I do not use the `output` as an `hex`? It will show the raw
data: `---> NPC Monster Check | ID b'\x00\x00\x00\x0f' |`

```yaml
Game:
  node:
    actions:
      0x80:
        title: NPC Monster Check
        structs:
          - name: ID
            type: chars
            size: 4
```

---

Take a little break for output and check the `reference` option. In the middle
time that you are parsing the data, some findings will be discovered for
example the ID types of the shop options. It is possible to map this
information and display as a text in the output. Adding `reference:
*node_shop_options` to your settings, it will take the section referring with
the ID `shop_options: &node_shop_options`. If the value is not in the map, it
will print as usual.

Given the raw data `\x00\xc5 \x00`, the output will be
`---> Shop store | ID Buy |`.

Given the raw data `\x00\xc5 \x01`, the output will be
`---> Shop store | ID Sell |`.

Given the raw data `\x00\xc5 \x5a`, the output will be
`---> Shop store | ID 0x5a |`.

```yaml
Game:
  node:
    references:
      shop_options: &node_shop_options
        0x0: 'Buy'
        0x1: 'Sell'
    actions:
      0xc5:
        title: Shop store
        structs:
          - name: ID
            type: unsigned char
            reference: *node_shop_options
            output:
              type: hex
              auto_zero_fill: Yes
```

---

Formatting the `output` is possible with these options `zero_fill`,
`auto_zero_fill`, `fill` and `fill_left`.

- `zero_fill` - Add zeros to the left for example if you have for digits as an
  output `0x12` and the property set to `8`, it will display:
  `00000x12`.
- `auto_zero_fill` - Add zeros to the left taking the type of the structure.
  For example if you have an `integer` with `byte size of 4`, but the value
  is `5`. The output without this option will be `0x05`, then if your next
  value is `123456789` the output will be `0x75bcd15`. Keep aligned the output
  and using the property `auto_zero_fill: Yes` it will display both numbers
  as`0000000x05` and `00x75bcd15` because the
  `integer` is `4 bytes` equal to `00 00 00 00` plus the pre-fix `0x`, it means
  10 digits.
- `fill` - Same as `zero_fill` but add blank spaces to the right of the value.
- `fill_left` - Same as the previous option but add blank spaces to the left of
  the value.

```yaml
Game:
  node:
    actions:
      0x146:
        title: NPC Dialog close
        structs:
          - type: unsigned int
            output:
              type: hex
              zero_fill: 20
          - type: unsigned int
            output:
              type: hex
              auto_zero_fill: Yes
          - type: unsigned int
            output:
              type: hex
              fill: 9
          - type: unsigned int
            output:
              type: hex
              fill_left: 17
```

## Endian

All the data coming from the network or server usually is big-endian, to read
this as the game interpretation needs to convert to little-endian. In this
example if you receive a raw data `ff 00 ab 14 36 f0 1f`. The parse should be:

- ID Action package: `ff 00` = `0x00ff` = `255`.
- ID Monster: `ab 14 36 f0` = `0xf03614ab`.
- Unknown: `1f` = `0x1f` = `31`.

Enjoy!


[pypi]: https://pypi.org/project/sniparinject/

[todo]: https://github.com/airvzxf/sniparinject/blob/main/TODO.md

[ascii-mana-image]: https://asciinema.org/a/R0mxcmrpWHzX96NDJyc7kyTDB.svg

[ascii-mana-link]: https://asciinema.org/a/R0mxcmrpWHzX96NDJyc7kyTDB

[structs]: https://docs.python.org/3/library/struct.html#format-characters
