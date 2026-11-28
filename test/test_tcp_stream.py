#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Unit Test.
"""
from src.sniparinject.core.tcp_stream import TcpStream


class TestTcpStream:
    def test___init__(self):
        # Arrange
        # Act
        stream = TcpStream()

        # Assert
        assert stream.next_sequence is None
        assert stream.buffer == b''

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

    def test_add_gap_starts_again(self):
        # Arrange
        stream = TcpStream()
        stream.add(100, b'\x01\x02')

        # Act
        stream.add(200, b'\x09')

        # Assert
        assert stream.buffer == b'\x09'
        assert stream.next_sequence == 201

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
