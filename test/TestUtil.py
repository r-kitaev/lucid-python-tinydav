# Unittests for util module.
# coding: utf-8
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
"""Unittests for util module."""

from __future__ import with_statement
from StringIO import StringIO
import unittest

from tinydav import HTTPClient, HTTPError
from tinydav import util

from Mock import injected
import Mock

MULTI = """\
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="a"

foo
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="b"

bar
--foobar--"""


MULTI_ISO = """\
--foobar
Content-Type: text/plain; charset="iso-8859-1"
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
Content-Disposition: form-data; name="a"

foo
--foobar
Content-Type: text/plain; charset="iso-8859-1"
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
Content-Disposition: form-data; name="b"

=C3=A4=C3=B6=C3=BC=C3=9F
--foobar--"""

MIME_ISO_EXPLICIT = """\
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="a"

foo
--foobar
Content-Type: text/plain; charset="iso-8859-1"
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
Content-Disposition: form-data; name="b"

=C3=A4=C3=B6=C3=BC=C3=9F
--foobar--"""


MIME_FILE = """\
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="a"

foo
--foobar
Content-Type: application/octet-stream
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: form-data; name="b"

VGhpcyBpcyBhIHRlc3QgZmlsZS4=
--foobar--"""


MIME_FILE_EXPLICIT = """\
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="a"

foo
--foobar
Content-Type: text/plain
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: form-data; name="b"

VGhpcyBpcyBhIHRlc3QgZmlsZS4=
--foobar--"""


MIME_FILE_NAME = """\
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="a"

foo
--foobar
Content-Type: application/octet-stream
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: form-data; name="b"; filename="test.txt"

VGhpcyBpcyBhIHRlc3QgZmlsZS4=
--foobar--"""


MIME_FILES = """\
--foobar
MIME-Version: 1.0
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit
Content-Disposition: form-data; name="a"

foo
--foobar
Content-Type: multipart/mixed; boundary="foobar-mixed"
MIME-Version: 1.0

--foobar-mixed
Content-Type: application/octet-stream
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: file; name="c"; filename="test2.txt"

VGhpcyBpcyBhbm90aGVyIHRlc3QgZmlsZS4=
--foobar-mixed
Content-Type: application/octet-stream
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: file; name="b"

VGhpcyBpcyBhIHRlc3QgZmlsZS4=
--foobar-mixed--
--foobar--"""


class UtilTestCase(unittest.TestCase):
    """Test util module."""
    def test_fake_http_request(self):
        """Test util.FakeHTTPReqest."""
        client = HTTPClient("localhost")
        headers = dict(a="1", b="2")
        fake = util.FakeHTTPRequest(client, "/foo/bar", headers)
        self.assertEqual(fake.get_full_url(), "http://localhost:80/foo/bar")
        self.assertEqual(fake.get_host(), "localhost")
        self.assertFalse(fake.is_unverifiable())
        self.assertEqual(fake.get_origin_req_host(), "localhost")
        self.assertEqual(fake.get_type(), "http")
        self.assertTrue(fake.has_header("a"))
        self.assertFalse(fake.has_header("foobar"))
        fake.add_unredirected_header("foobar", "baz")
        self.assertTrue(fake.has_header("foobar"))

    def test_make_absolute(self):
        """Test util.make_absolute function."""
        mockclient = Mock.Omnivore()
        mockclient.protocol = "http"
        mockclient.host = "localhost"
        mockclient.port = 80
        expect = "http://localhost:80/foo/bar"
        self.assertEqual(util.make_absolute(mockclient, "/foo/bar"), expect)

    def test_extract_namespace(self):
        """Test util.extrace_namespace."""
        self.assertEqual(util.extract_namespace("{foo}bar"), "foo")
        self.assertEqual(util.extract_namespace("bar"), None)

    def test_get_depth(self):
        """Test util.get_depth."""
        # test unrestricted
        self.assertEqual(util.get_depth("0"), "0")
        self.assertEqual(util.get_depth(0), "0")
        self.assertEqual(util.get_depth("1"), "1")
        self.assertEqual(util.get_depth(1), "1")
        self.assertEqual(util.get_depth("InFiNiTy"), "infinity")
        self.assertRaises(ValueError, util.get_depth, "illegal")
        # test restricted
        restricted = ("0", "infinity")
        self.assertEqual(util.get_depth("0", restricted), "0")
        self.assertEqual(util.get_depth(0, restricted), "0")
        self.assertRaises(ValueError, util.get_depth, "1", restricted)
        self.assertRaises(ValueError, util.get_depth, 1, restricted)
        self.assertEqual(util.get_depth("InFiNiTy", restricted), "infinity")

    def test_get_cookie_response(self):
        """Test util.get_cookie_response."""
        response = Mock.Omnivore()
        response.response = Mock.Omnivore()
        response.response.msg = "The message"
        self.assertEqual(util.get_cookie_response(response), response.response)
        # must extract response object from HTTPError
        error = HTTPError(response)
        self.assertEqual(util.get_cookie_response(error), response.response)

    def test_parse_authenticate(self):
        """Test util.parse_authenticate."""
        # basic auth
        basic = 'Basic realm="restricted"'
        authdata = util.parse_authenticate(basic)
        self.assertEqual(authdata.get("schema"), "Basic")
        self.assertEqual(authdata.get("realm"), "restricted")
        self.assertEqual(authdata.get("domain"), None)
        self.assertEqual(authdata.get("nonce"), None)
        self.assertEqual(authdata.get("opaque"), None)
        self.assertEqual(authdata.get("stale"), None)
        self.assertEqual(authdata.get("algorithm"), None)
        # digest auth
        digest = 'Digest realm="restricted" domain="foo.de" nonce="abcd1234"'\
                 'opaque="qwer4321" stale=false algorithm="MD5"'
        authdata = util.parse_authenticate(digest)
        self.assertEqual(authdata.get("schema"), "Digest")
        self.assertEqual(authdata.get("realm"), "restricted")
        self.assertEqual(authdata.get("domain"), "foo.de")
        self.assertEqual(authdata.get("nonce"), "abcd1234")
        self.assertEqual(authdata.get("opaque"), "qwer4321")
        self.assertEqual(authdata.get("stale"), "false")
        self.assertEqual(authdata.get("algorithm"), "MD5")
        # digest auth missing something
        digest = 'Digest realm="restricted" domain="foo.de" nonce="abcd1234"'\
                 'opaque="qwer4321" algorithm="MD5"'
        authdata = util.parse_authenticate(digest)
        self.assertEqual(authdata.get("schema"), "Digest")
        self.assertEqual(authdata.get("realm"), "restricted")
        self.assertEqual(authdata.get("domain"), "foo.de")
        self.assertEqual(authdata.get("nonce"), "abcd1234")
        self.assertEqual(authdata.get("opaque"), "qwer4321")
        self.assertEqual(authdata.get("stale"), None)
        self.assertEqual(authdata.get("algorithm"), "MD5")
        # broken authenticate header
        authdata = util.parse_authenticate("Nothing")
        self.assertEqual(authdata, dict())

    def test_make_multipart(self):
        """Test util.make_multipart."""
        # form-data
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b="bar")
            (headers, multi) = util.make_multipart(content)
            self.assertEqual(
                headers["Content-Type"],
                'multipart/form-data; boundary="foobar"'
            )
            self.assertEqual(multi, MULTI)
        # form-data with iso-8859-1
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b="äöüß")
            (headers, multi) = util.make_multipart(content, "iso-8859-1")
            self.assertEqual(
                headers["Content-Type"],
                'multipart/form-data; boundary="foobar"'
            )
            self.assertEqual(multi, MULTI_ISO)
        # form-data with explicit iso-8859-1
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b=("äöüß", "iso-8859-1"))
            (headers, multi) = util.make_multipart(content)
            self.assertEqual(
                headers["Content-Type"],
                'multipart/form-data; boundary="foobar"'
            )
            self.assertEqual(multi, MIME_ISO_EXPLICIT)
        # post one file
        sio = StringIO("This is a test file.")
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b=sio)
            (headers, multi) = util.make_multipart(content)
            self.assertEqual(
                headers["Content-Type"],
                'multipart/form-data; boundary="foobar"'
            )
            self.assertEqual(multi, MIME_FILE)
        # post one file with filename
        sio = StringIO("This is a test file.")
        sio.name = "test.txt"
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b=sio)
            (headers, multi) = util.make_multipart(content, with_filenames=True)
            self.assertEqual(
                headers["Content-Type"],
                'multipart/form-data; boundary="foobar"'
            )
            self.assertEqual(multi, MIME_FILE_NAME)
        # post one file with explicit content-type
        sio = StringIO("This is a test file.")
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b=(sio, "text/plain"))
            (headers, multi) = util.make_multipart(content)
            self.assertEqual(
                headers["Content-Type"],
                'multipart/form-data; boundary="foobar"'
            )
            self.assertEqual(multi, MIME_FILE_EXPLICIT)
        # post two files, one with filename
        sio = StringIO("This is a test file.")
        sio2 = StringIO("This is another test file.")
        sio2.name = "test2.txt"
        context = dict(MIMEMultipart=Mock.FakeMIMEMultipart())
        with injected(util.make_multipart, **context):
            content = dict(a="foo", b=sio, c=sio2)
            (headers, multi) = util.make_multipart(content, with_filenames=True)
            self.assertEqual(
                headers["Content-Type"],
                'multipart/form-data; boundary="foobar"'
            )
            self.assertEqual(multi, MIME_FILES)
