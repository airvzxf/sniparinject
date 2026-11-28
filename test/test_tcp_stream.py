#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Unit Test.
"""
from src.sniparinject.core.tcp_stream import MAX_PENDING_SEGMENTS, TcpStream


class TestTcpStream:
    def test___init__(self):
        # Arrange
        # Act
        stream = TcpStream()

        # Assert
        assert stream.next_sequence is None
        assert stream.buffer == b''
        assert stream.pending == {}

    def test_add_in_order(self):
        # Arrange
        stream = TcpStream()

        # Act
        stream.add(100, b'\x01\x02')
        stream.add(102, b'\x03')

        # Assert
        assert stream.buffer == b'\x01\x02\x03'
        assert stream.next_sequence == 103

    def test_add_skip_retransmit(self):
        # Arrange
        stream = TcpStream()
        stream.add(100, b'\x01\x02')

        # Act
        stream.add(100, b'\x01\x02')

        # Assert
        assert stream.buffer == b'\x01\x02'
        assert stream.next_sequence == 102

    def test_add_retransmit_with_new_bytes(self):
        # Arrange
        stream = TcpStream()
        stream.add(100, b'\x01\x02')

        # Act
        stream.add(101, b'\x02\x03\x04')

        # Assert
        assert stream.buffer == b'\x01\x02\x03\x04'
        assert stream.next_sequence == 104

    def test_add_after_gap_waits(self):
        # Arrange
        stream = TcpStream()
        stream.add(100, b'\x01\x02')

        # Act
        stream.add(200, b'\x09')

        # Assert
        assert stream.buffer == b'\x01\x02'
        assert stream.next_sequence == 102
        assert stream.pending == {200: b'\x09'}

    def test_add_out_of_order_fills_gap(self):
        # Arrange: the order of a live capture, the segment at 5882 arrives late.
        stream = TcpStream()
        stream.add(5875, b'\x01' * 7)
        stream.add(5973, b'\x03' * 54)
        stream.add(6027, b'\x04' * 12)

        # Act
        stream.add(5882, b'\x02' * 91)

        # Assert
        assert stream.buffer == b'\x01' * 7 + b'\x02' * 91 + b'\x03' * 54 + b'\x04' * 12
        assert stream.next_sequence == 6039
        assert not stream.pending

    def test_add_pending_keeps_longer_segment(self):
        # Arrange
        stream = TcpStream()
        stream.add(100, b'\x01')
        stream.add(110, b'\x05\x06')

        # Act
        stream.add(110, b'\x05')
        stream.add(101, b'\x02' * 9)

        # Assert
        assert stream.buffer == b'\x01' + b'\x02' * 9 + b'\x05\x06'
        assert not stream.pending

    def test_add_pending_overlap(self):
        # Arrange
        stream = TcpStream()
        stream.add(100, b'\x01')
        stream.add(103, b'\x04\x05')

        # Act
        stream.add(101, b'\x02\x03\x04')

        # Assert
        assert stream.buffer == b'\x01\x02\x03\x04\x05'
        assert stream.next_sequence == 105

    def test_add_gap_not_filled_starts_again(self):
        # Arrange
        stream = TcpStream()
        stream.add(100, b'\x01\x02')

        # Act: the bytes from 102 to 199 never arrive.
        for index in range(MAX_PENDING_SEGMENTS + 1):
            stream.add(300 - index * 10, bytes([index]) * 10)

        # Assert
        assert stream.buffer == b''.join(bytes([index]) * 10 for index in reversed(range(MAX_PENDING_SEGMENTS + 1)))
        assert stream.next_sequence == 310
        assert not stream.pending

    def test_add_sequence_wraps(self):
        # Arrange
        stream = TcpStream()
        stream.add(2 ** 32 - 1, b'\x01\x02')

        # Act
        stream.add(1, b'\x03')

        # Assert
        assert stream.buffer == b'\x01\x02\x03'
        assert stream.next_sequence == 2

    def test_pop(self):
        # Arrange
        stream = TcpStream()
        stream.add(0, b'\x01\x02\x03')

        # Act
        data = stream.pop(2)

        # Assert
        assert data == b'\x01\x02'
        assert stream.buffer == b'\x03'
