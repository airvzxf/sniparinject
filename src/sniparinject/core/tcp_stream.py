#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Rebuild the data of one direction of a TCP connection.
"""

SEQUENCE_SIZE = 2 ** 32


class TcpStream:
    """
    Join the TCP segments of one direction in sequence order.

    A game packet can be split across two or more TCP segments, and one
    segment can hold several game packets. The stream keeps the bytes that
    are not parsed yet, so the next segment completes them.
    """

    def __init__(self) -> None:
        """
        Start an empty stream.

        :rtype: None
        :return: Nothing.
        """
        self.next_sequence: int | None = None
        self.buffer = b''

    def add(self, sequence: int, payload: bytes) -> None:
        """
        Append the new bytes of a TCP segment to the stream.

        A retransmitted segment adds only the bytes that are not in the
        stream yet. A segment after a gap (a lost segment, or a new
        connection) drops the pending bytes and starts the stream again.

        :type sequence: int
        :param sequence: The TCP sequence number of the segment.

        :type payload: bytes
        :param payload: The TCP payload of the segment.

        :rtype: None
        :return: Nothing.
        """
        if self.next_sequence is None:
            self.next_sequence = sequence

        offset = (self.next_sequence - sequence) % SEQUENCE_SIZE
        if offset >= SEQUENCE_SIZE // 2:
            self.buffer = b''
            offset = 0
        elif offset >= len(payload):
            return

        self.buffer += payload[offset:]
        self.next_sequence = (sequence + len(payload)) % SEQUENCE_SIZE

    def pop(self, size: int) -> bytes:
        """
        Take the first bytes of the stream.

        :type size: int
        :param size: The number of bytes to take.

        :rtype: bytes
        :return: The bytes taken from the stream.
        """
        data = self.buffer[:size]
        self.buffer = self.buffer[size:]

        return data
