# To-Do's List

## General

- [ ] `ELF64` binary file in Linux.
    - [ ] Create executable file in Linux.
    - [ ] Build the executable file in the GitHub workflows.
- [ ] Documentation for the different options in settings.
    - [x] Types: [Python Structs][structs].
    - [ ] Linux: Man page.
- [ ] Add injection of packages.
    - [ ] Run a thread which capture the keyboard events and do some
      injections.
- [ ] Add screen filter. Keep internally the outputs and provide commands to
  the user to search specific outputs.

- [x] Add UDP protocol for the sniffer.
- [x] Core module. Extractions and refactors.
    - [x] Create a Python packages (https://pypi.org/) for the `core` module.
        - [x] Name of the project: `SniParInject` = Sniffer, Parser and Inject.

## Feature

### Settings are the goodies

- [x] Control all from settings.
    - [x] Load settings file every iteration.
    - [x] Create generic source code which take all the information and rules
      from the `settings.yml` file.
    - [x] Override text for host, node and error.

[structs]: https://docs.python.org/3/library/struct.html#format-characters
