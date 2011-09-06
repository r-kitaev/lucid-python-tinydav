# Unittests for exception module.
# Copyright (C) 2009  Manuel Hermann <manuel-hermann@gmx.net>
#
# This file is part of tinydav.
#
# tinydav is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""Unittests for exception module."""

import unittest

from tinydav.exception import HTTPError
import Mock


class HTTTPErrorTestCase(unittest.TestCase):
    """Test HTTPErrro exception class."""
    def setUp(self):
        """Setup the tests."""
        self.response = 400
        self.err = HTTPError(self.response)

    def test_init(self):
        """Test initializing the HTTPError class."""
        self.assertEqual(self.err.response, self.response)

    def test_repr(self):
        """Test HTTPError.__repr__."""
        self.assertEqual(repr(self.err), "<HTTPError: 400>")

    def test_str(self):
        """Test HTTPError.__str__."""
        response = Mock.Response()
        response.statusline = "HTTP/1.1 400 Some error"
        err = HTTPError(response)
        self.assertEqual(str(err), "HTTP/1.1 400 Some error")

