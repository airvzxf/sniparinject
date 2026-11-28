#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Parse the game data.
"""
from logging import getLogger
from struct import unpack, unpack_from
from typing import Any, NoReturn, cast

from scapy.compat import raw
from scapy.layers.l2 import Ether
from scapy.packet import Raw

# pylint: disable=import-error
from .errors import PARSE_ERRORS, GameError, SettingsError
from .settings import Settings
from .structs import STRUCT_TYPES
from .text_style import TextStyle
from .utility import Utility

logger = getLogger(__name__)


class Game:
    """
    Parse the game data.
    """

    def __init__(self, settings_path: str, is_host: bool, packet: Ether | bytes):
        """
        Parse the game data.

        :type settings_path: str
        :param settings_path: The file path with all the settings.

        :type is_host: bool
        :param is_host: Is this response by the host?

        :type packet: Ether | bytes
        :param packet: Ethernet packet, or the game data already taken from it.

        :rtype: None
        :return: Nothing.
        """
        data = packet if isinstance(packet, bytes) else raw(cast(Raw, packet.getlayer(Raw)))
        self.raw_data = data
        self.raw_data_copy = data
        self.settings_path = settings_path
        self.request = 'host' if is_host else 'node'
        self.display_message = True

    def start(self) -> None:
        """
        Start to process the network packets sniffer and parse.

        :rtype: None
        :return: Nothing.
        """
        try:
            self._parse_packets()
        except PARSE_ERRORS as error:
            error_message, error_location = self._extract_exception(error)
            error_location = f'Class Game{error_location}'
            self._print_error(error_message, error_location)

    @classmethod
    def complete_length(cls, settings_path: str, is_host: bool, data: bytes) -> int:
        """
        Measure how many bytes at the start of the data are complete packets.

        The size of each packet comes from its action: the id plus its structs,
        or the length after the id when it is a variable length packet. The
        bytes after the last complete packet wait for the next TCP segment.
        An unknown id, or settings that can not give a size, take all the
        data, so the parser shows it as before.

        :type settings_path: str
        :param settings_path: The file path with all the settings.

        :type is_host: bool
        :param is_host: Is this data sent by the host?

        :type data: bytes
        :param data: The game data, which can end with an incomplete packet.

        :rtype: int
        :return: The number of bytes of the complete packets.
        """
        game = cls(settings_path, is_host, data)
        try:
            actions = game._get_settings().get('actions') or {}
        except PARSE_ERRORS:
            return len(data)

        offset = 0
        while len(data) - offset >= 2:
            packet_id, = unpack_from('<H', data, offset)
            if packet_id not in actions:
                return len(data)

            size = game._packet_size(actions.get(packet_id) or {}, data, offset)
            if size is None:
                return len(data)
            if offset + size > len(data):
                break
            offset += size

        return offset

    def _packet_size(self, action: dict, data: bytes, offset: int) -> int | None:
        """
        Get the size of the packet that starts at the offset.

        A variable length packet without its whole header returns the header
        size, so the caller waits for more data.

        :type action: dict
        :param action: Properties of the action of the packet.

        :type data: bytes
        :param data: The game data.

        :type offset: int
        :param offset: The position of the packet id in the data.

        :rtype: int | None
        :return: The size of the packet, or None when it can not be known.
        """
        header_size = 4
        if action.get('variable_length'):
            if len(data) - offset < header_size:
                return header_size
            size, = unpack_from('<H', data, offset + 2)
            return size if size >= header_size else None

        try:
            _, structs_size = self._join_structs(self._validate_structs(action), '')
        except PARSE_ERRORS:
            return None

        return 2 + structs_size

    @staticmethod
    def _extract_exception(error: Exception) -> tuple[str, str]:
        """
        Extract the information from the exception error.

        :type error: Exception
        :param error: Error exception.

        :rtype: tuple[str, str]
        :return: Return the the error message and the location.
        """
        location = ''

        if len(error.args) == 2:
            message = error.args[0]
            location += error.args[1]
        else:
            message = str(error)

        return message, location

    def _raise_exception(self, error: Exception, location: str = '') -> NoReturn:
        """
        Raise a game error taking the information from the error.

        :type error: Exception
        :param error: Error exception.

        :type location: str
        :param location: The cascade classes and functions where the error occurred.

        :rtype: NoReturn
        :return: It always raises a GameError, or the SettingsError it was given.
        """
        message, extracted_location = self._extract_exception(error)
        full_location = f'{location}{extracted_location}'
        error_class = type(error) if isinstance(error, GameError) else GameError
        raise error_class(message, full_location) from error

    def _print_error(self, error: str, location: str) -> None:
        """
        Print the error.

        :type error: str
        :param error: Error message.

        :type location: str
        :param location: The cascade classes and functions where the error occurred.

        :rtype: None
        :return: Nothing.
        """
        message = Utility.text_error_format(f'Error {self.request.upper()}: {error}')
        location = Utility.text_error_format(f'Location: {location}')
        data = Utility.text_error_format(f'Data: {self.raw_data.hex()}')
        data_copy = Utility.text_error_format(f'Data Error: {self.raw_data_copy.hex()}')
        logger.error('%s\n%s\n%s\n%s\n', message, location, data, data_copy)

    def _parse_packets(self) -> None:
        """
        Start the parse of the packets.

        :rtype: None
        :return: Nothing.
        """
        exception_location = ' -> _parse_packets()'
        while True:
            settings = {}
            try:
                settings = self._get_settings()
            except PARSE_ERRORS as error:
                self._raise_exception(error, exception_location)

            packet_id, = unpack('<H', self._get_data(2))
            actions = settings.get('actions') or {}
            if packet_id not in actions:
                if self.display_message:
                    print(f'{self.request.upper()}'
                          f' | ID {hex(packet_id)}'
                          f' | {self.raw_data_copy.hex()}')
                    print(f'     |-> {self.raw_data.hex()}')
                return

            action = actions.get(packet_id) or {}
            message = ''
            try:
                message = self._execute_action(action)
            except PARSE_ERRORS as error:
                self._raise_exception(error, exception_location)
            self._display_message(action, message)

            if len(self.raw_data_copy) < 1:
                return

    def _get_settings(self) -> dict:
        """
        Validate and return the settings dictionary.

        :rtype: dict
        :return: The actions with the settings.
        """
        settings_exception = SettingsError('The Game settings are missing.',
                                           ' -> Settings(...).get(\'Game\')')

        general_settings: dict = {}
        try:
            general_settings = Settings(self.settings_path).get_dictionary().get('Game') or {}
        except PARSE_ERRORS:
            self._raise_exception(settings_exception)

        if len(general_settings) < 1:
            self._raise_exception(settings_exception)

        if self.request == 'host':
            settings = general_settings.get('host') or {}
        else:
            settings = general_settings.get('node') or {}

        display_message = settings.get('display_message')
        self.display_message = True if display_message is None else bool(display_message)

        return settings

    def _execute_action(self, action: dict) -> str:
        """
        Create an output given the action settings.

        :type action: dict
        :param action: Properties of the actions.

        :rtype: str
        :return: Message of this action.
        """
        exception_location = ' -> _execute_action()'

        self._validate_action(action, exception_location)
        message = self._generate_title_action(action)

        next_packets = None
        if action.get('variable_length'):
            message_length, next_packets = self._split_variable_length(exception_location)
            message += message_length

        structs = self._validate_structs(action)
        if structs:
            message += self._convert_structs_to_format(structs, exception_location)

        if next_packets is not None:
            if len(self.raw_data_copy) > 0:
                message += self.text_format(' Data', TextStyle.BOLD)
                message += self.text_format(f' {self.raw_data_copy.hex()}', TextStyle.LIGHT)
                message += self.text_format(' |')
            self.raw_data_copy = next_packets

        return message

    def _split_variable_length(self, exception_location: str) -> tuple[str, bytes]:
        """
        Read the length of a variable length packet and keep only its body.

        The two bytes after the packet id are the total length of the packet,
        including the id and the length itself. After this call the data to
        parse is the body of the packet, and the returned bytes are the next
        packets.

        :type exception_location: str
        :param exception_location: The function where the exception occurred.

        :rtype: tuple[str, bytes]
        :return: The message with the length and the data of the next packets.
        """
        header_size = 4
        if len(self.raw_data_copy) < 2:
            self._raise_exception(
                GameError('The variable length packet has no length.', exception_location)
            )

        length, = unpack('<H', self._get_data(2))
        body_size = length - header_size
        if body_size < 0 or body_size > len(self.raw_data_copy):
            self._raise_exception(
                GameError(
                    f'The packet length ({length}) does not match the data'
                    f' ({len(self.raw_data_copy) + header_size} bytes).',
                    exception_location)
            )

        next_packets = self.raw_data_copy[body_size:]
        self.raw_data_copy = self.raw_data_copy[:body_size]

        message = self.text_format(' Length', TextStyle.BOLD)
        message += self.text_format(f' {length}', TextStyle.LIGHT)
        message += self.text_format(' |')

        return message, next_packets

    def _validate_action(self, action: dict, exception_location: str) -> None:
        """
        Validate the action.

        :type action: dict
        :param action: Properties of the actions.

        :type exception_location: dict
        :param exception_location: The function where the exception occurred.

        :rtype: None
        :return: Nothing
        """
        if len(action.keys()) == 0:
            self._raise_exception(
                GameError('The action is empty.', exception_location)
            )

    @staticmethod
    def _validate_structs(action: dict) -> list:
        """
        Validate the structs.

        :type action: dict
        :param action: Properties of the actions.

        :rtype: list
        :return: The list of the structs.
        """
        return action.get('structs') or []

    def _generate_title_action(self, action: dict) -> str:
        """
        Generate the title of the action.

        :type action: dict
        :param action: Properties of the actions.

        :rtype: str
        :return: Message of this action.
        """
        title = action.get('title') or ''
        direction = '<--' if self.request == 'host' else '-->'
        message = self.text_format(f'{direction} {title}', TextStyle.TITLE)
        message += self.text_format(' |')

        return message

    def _join_structs(self, structs: list, exception_location: str) -> tuple[str, int]:
        """
        Join all the structs and return useful information.

        :type structs: list
        :param structs: List with the structs information.

        :type exception_location: dict
        :param exception_location: The function where the exception occurred.

        :rtype: tuple[str, int]
        :return: Return the formatted message and the size in bytes.
        """
        formatted_struct = ''
        size = 0
        for struct in structs:
            struct_type_setting = struct.get('type') or None
            if struct_type_setting is None:
                self._raise_exception(
                    GameError(
                        f'The struct type is missing. Struct -> {struct}.',
                        exception_location)
                )

            struct_repeat_count = int(struct.get('size') or 0)
            struct_type, struct_size = self._get_struct(struct_type_setting, struct_repeat_count)
            formatted_struct += struct_type
            size += struct_size

        return formatted_struct, size

    def _convert_structs_to_format(self, structs: list, exception_location: str) -> str:
        """
        Convert the structs into message format.

        :type structs: list
        :param structs: The list with the structs.

        :type exception_location: dict
        :param exception_location: The function where the exception occurred.

        :rtype: str
        :return: Message of this action.
        """
        message = ''
        structs_format, structs_size = self._join_structs(structs, exception_location)

        for index, variable in enumerate(
                unpack(f'<{structs_format}', self._get_data(structs_size))):
            struct: dict = structs[index]
            message += self._get_struct_name_format(struct)

            struct_output: dict | None = struct.get('output') or None
            struct_reference: dict | None = struct.get('reference') or None
            if struct_reference and variable in struct_reference:
                variable = struct_reference[variable]
                struct_output = {}

            if struct_output:
                variable = self._get_struct_output_type(struct_output, variable)
                variable = self._get_struct_output_zero_fill(struct_output, variable)
                variable = self._get_struct_output_auto_zero_fill(
                    struct_output, variable, struct.get('type') or '')
                variable = self._get_struct_output_fill(struct_output, variable)
                variable = self._get_struct_output_fill_left(struct_output, variable)

            message += self.text_format(f' {variable}', TextStyle.LIGHT)
            message += self.text_format(' |')

        return message

    def _get_struct_name_format(self, struct: dict) -> str:
        """
        Get the struct name with format.

        :type struct: dict
        :param struct: The struct information of the output.

        :rtype: str
        :return: Message with format.
        """
        struct_name: str | None = struct.get('name') or None
        if struct_name:
            return self.text_format(f' {struct_name}', TextStyle.BOLD)

        return ''

    @staticmethod
    def _get_struct_output_type(struct: dict, variable: Any) -> Any:
        """
        Get the struct output type with format.

        :type struct: dict
        :param struct: The struct information of the output.

        :type struct: Any
        :param struct: The variable which will be replaced.

        :rtype: Any
        :return: Variable with the format.
        """
        struct_output_type: str | None = struct.get('type') or None
        if struct_output_type and struct_output_type.lower() == 'hex':
            return variable.hex() if isinstance(variable, bytes) else hex(variable)

        is_text = struct_output_type and struct_output_type.lower() == 'text'
        if is_text and isinstance(variable, bytes):
            return variable.split(b'\x00', 1)[0].decode('utf-8', errors='replace')

        return variable

    @staticmethod
    def _get_struct_output_zero_fill(struct: dict, variable: Any) -> Any:
        """
        Get the struct output of zero fill with format.

        :type struct: dict
        :param struct: The struct information of the output.

        :type struct: Any
        :param struct: The variable which will be replaced.

        :rtype: Any
        :return: Variable with the format.
        """
        output_zero_fill: int = struct.get('zero_fill') or 0
        if output_zero_fill > 0:
            return Game._zero_fill(variable, output_zero_fill)

        return variable

    @staticmethod
    def _zero_fill(variable: Any, width: int) -> str:
        """
        Add zeros to the left until the text has the given width.
        For a hexadecimal value the zeros go after the `0x` prefix.

        :type variable: Any
        :param variable: The variable which will be filled.

        :type width: int
        :param width: The width of the text with the zeros.

        :rtype: str
        :return: The text with the zeros, for example `0x0012`.
        """
        text = str(variable)
        sign = '-' if text.startswith('-') else ''
        digits = text[len(sign):]
        if digits.startswith('0x'):
            return f'{sign}0x{digits[2:].zfill(width - len(sign) - 2)}'

        return text.zfill(width)

    def _get_struct_output_auto_zero_fill(self, struct: dict,
                                          variable: Any, struct_type: str) -> Any:
        """
        Get the struct output of auto zero fill with format.

        :type struct: dict
        :param struct: The struct information of the output.

        :type struct: Any
        :param struct: The variable which will be replaced.

        :type struct_type: str
        :param struct_type: The type of the struct.

        :rtype: Any
        :return: Variable with the format.
        """
        output_auto_zero_fill: bool = struct.get('auto_zero_fill') or False
        if output_auto_zero_fill:
            _, struct_size = self._get_struct(struct_type or '')
            struct_size *= 2
            struct_size += 2
            return self._zero_fill(variable, struct_size)

        return variable

    @staticmethod
    def _get_struct_output_fill(struct: dict, variable: Any) -> Any:
        """
        Get the struct output with fill left format.

        :type struct: dict
        :param struct: The struct information of the output.

        :type struct: Any
        :param struct: The variable which will be replaced.

        :rtype: Any
        :return: Variable with the format.
        """
        output_fill: int = struct.get('fill') or 0
        if output_fill > 0:
            return str(variable).ljust(output_fill)

        return variable

    @staticmethod
    def _get_struct_output_fill_left(struct: dict, variable: Any) -> Any:
        """
        Get the struct output with fill left format.

        :type struct: dict
        :param struct: The struct information of the output.

        :type struct: Any
        :param struct: The variable which will be replaced.

        :rtype: Any
        :return: Variable with the format.
        """
        output_fill_left: int = struct.get('fill_left') or 0
        if output_fill_left > 0:
            variable = str(variable).rjust(output_fill_left)

        return variable

    def _get_struct(self, struct_type: str, repeat_count: int = 1) -> tuple[str, int]:
        """
        Map of the structs with the correlated symbol.

        :type struct_type: str
        :param struct_type: Full name description.

        :type repeat_count: int
        :param repeat_count: Times that the symbol will repeat.

        :rtype: tuple[str, int]
        :return: The struct symbol and its size.
        """
        exception_location = ' -> _get_struct()'

        struct = STRUCT_TYPES.get(struct_type.lower()) if isinstance(struct_type, str) else None
        if struct is None:
            self._raise_exception(
                GameError(
                    f'The struct type ({struct_type}) is not defined in the map of structs.',
                    exception_location)
            )

        symbol, size = struct
        if repeat_count > 1:
            size *= repeat_count
            symbol = f'{repeat_count}{symbol}'

        return symbol, size

    def _get_data(self, size: int) -> bytes:
        """
        Split the data in two parts.
        The first one is returned the second is updated in the referenced variable.

        :type size: int
        :param size: Size of data which will split.

        :rtype: bytes
        :return: The split data.
        """
        data = self.raw_data_copy[:size]
        self.raw_data_copy = self.raw_data_copy[size:]

        return data

    def _display_message(self, action: dict, message: str) -> None:
        """
        Print message in the console.

        :type message: str
        :param message: Size of data which will split.

        :rtype: None
        :return: Nothing.
        """
        action_display_info = action.get('display_message')

        if self.display_message and action_display_info is None:
            print(message)
            return

        if action_display_info:
            print(message)
            return

    def text_format(self, text: str, style: TextStyle = TextStyle.NORMAL) -> str:
        """
        Prints the text format for host output.

        Style:
        - NORMAL = '0'
        - BOLD = '1'
        - LIGHT = '2'
        - ITALIC = '3'
        - UNDERLINE = '4'
        - SELECTED = '7'
        - STRIKETHROUGH = '9'
        - DOUBLE_UNDERLINE = '21'

        :type text: str
        :param text: The text which will be format.

        :type style: TextStyle
        :param style: Set the style of the text.

        :rtype: str
        :return: The format code.
        """
        format_code = ''

        if style == TextStyle.TITLE:
            format_code += '00;93;'

        if style == TextStyle.NORMAL:
            format_code += '00;30;'

        if style == TextStyle.BOLD:
            format_code += '00;37;'

        if style == TextStyle.LIGHT:
            format_code += '00;96;'

        format_code += '44' if self.request == 'host' else '100'

        return f'\x1b[{format_code}m{text}\x1b[0m'
