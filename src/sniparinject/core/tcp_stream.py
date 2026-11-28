#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Rebuild the data of one direction of a TCP connection.
"""
from typing import cast

SEQUENCE_SIZE = 2 ** 32
MAX_PENDING_SEGMENTS = 16


class TcpStream:
    """
    Join the TCP segments of one direction in sequence order.

    A game packet can be split across two or more TCP segments, and one
    segment can hold several game packets. The stream keeps the bytes that
    are not parsed yet, so the next segment completes them.
    """

    def __init__(self, next_sequence: int | None = None) -> None:
        """
        Start an empty stream.

        :type next_sequence: int | None
        :param next_sequence: The sequence number of the first data byte,
        known from the SYN of the connection. None takes the sequence of the
        first segment added.

        :rtype: None
        :return: Nothing.
        """
        self.next_sequence = next_sequence
        self.first_sequence = next_sequence
        self.buffer = b''
        self.pending: dict[int, bytes] = {}

    def add(self, sequence: int, payload: bytes) -> None:
        """
        Append the new bytes of a TCP segment to the stream.

        A retransmitted segment adds only the bytes that are not in the
        stream yet. A segment after a gap (it arrived before an earlier
        one) waits until the gap is filled. When more than
        MAX_PENDING_SEGMENTS segments wait, the missing bytes count as lost:
        the stream drops its bytes and starts again at the first waiting
        segment.

        :type sequence: int
        :param sequence: The TCP sequence number of the segment.

        :type payload: bytes
        :param payload: The TCP payload of the segment.

        :rtype: None
        :return: Nothing.
        """
        if self.next_sequence is None:
            self.next_sequence = sequence
            self.first_sequence = sequence

        if self._distance(sequence) >= SEQUENCE_SIZE // 2:
            if len(payload) > len(self.pending.get(sequence, b'')):
                self.pending[sequence] = payload
            if len(self.pending) > MAX_PENDING_SEGMENTS:
                self._skip_gap()
            return

        self._append(sequence, payload)
        self._add_pending()

    def _distance(self, sequence: int) -> int:
        """
        Count how many bytes of the stream are before the sequence number.

        :type sequence: int
        :param sequence: A TCP sequence number.

        :rtype: int
        :return: The bytes from the sequence to the next expected byte. A
        value of half the sequence space or more means that the sequence is
        after the next expected byte.
        """
        # Only called after the first segment has set the next sequence.
        return (cast(int, self.next_sequence) - sequence) % SEQUENCE_SIZE

    def _append(self, sequence: int, payload: bytes) -> None:
        """
        Append the bytes of a segment that start at or before the next
        expected byte.

        :type sequence: int
        :param sequence: The TCP sequence number of the segment.

        :type payload: bytes
        :param payload: The TCP payload of the segment.

        :rtype: None
        :return: Nothing.
        """
        offset = self._distance(sequence)
        if offset >= len(payload):
            return

        self.buffer += payload[offset:]
        self.next_sequence = (sequence + len(payload)) % SEQUENCE_SIZE

    def _add_pending(self) -> None:
        """
        Append the waiting segments that the stream reached.

        :rtype: None
        :return: Nothing.
        """
        reached = True
        while reached:
            reached = False
            for sequence in list(self.pending):
                if self._distance(sequence) < SEQUENCE_SIZE // 2:
                    self._append(sequence, self.pending.pop(sequence))
                    reached = True

    def _skip_gap(self) -> None:
        """
        Drop the bytes before a gap that was not filled and start again at
        the first waiting segment.

        :rtype: None
        :return: Nothing.
        """
        self.buffer = b''
        start = cast(int, self.next_sequence)
        self.next_sequence = min(
            self.pending, key=lambda sequence: (sequence - start) % SEQUENCE_SIZE
        )
        self._add_pending()

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
