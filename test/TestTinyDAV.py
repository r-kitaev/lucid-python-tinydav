# Unittests for tinydav lib.
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
"""Unittests for tinydav lib."""

from __future__ import with_statement
from cookielib import CookieJar
from StringIO import StringIO
from xml.etree.ElementTree import ElementTree
import hashlib
import httplib
import urllib
import socket
import sys
import tinydav
import unittest

from tinydav import HTTPError, HTTPUserError, HTTPServerError
from tinydav import HTTPClient
from tinydav import HTTPResponse
from tinydav import CoreWebDAVClient
from tinydav import ExtendedWebDAVClient
from tinydav import WebDAVResponse
from tinydav import WebDAVLockResponse
from tinydav import MultiStatusResponse
from Mock import injected, replaced
import Mock

PYTHONVERSION = sys.version_info[:2] # (2, 5) or (2, 6)

if PYTHONVERSION >= (2, 7):
    from xml.etree.ElementTree import ParseError
else:
    from xml.parsers.expat import ExpatError as ParseError

MULTISTATUS = """\
<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:dc="DC:">
<D:response>
<D:href>/3/38/38f/38fa476aa97a4b2baeb41a481fdca00b</D:href>
<D:propstat>
<D:prop>
<D:getetag>6ca7-364-475e65375ce80</D:getetag>
<dc:created/>
<dc:resource/>
<dc:author/>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>
"""

# unbound prefix
MULTISTATUS_BROKEN = """\
<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>/3/38/38f/38fa476aa97a4b2baeb41a481fdca00b</D:href>
<D:propstat>
<D:prop>
<D:getetag>6ca7-364-475e65375ce80</D:getetag>
<dc:created/>
<dc:resource/>
<dc:author/>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>
"""

REPORT = """\
<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>/his/23/ver/V1</D:href>
<D:propstat>
<D:prop>
<D:version-name>V1</D:version-name>
<D:creator-displayname>Fred</D:creator-displayname>
<D:successor-set>
<D:href>/his/23/ver/V2</D:href>
</D:successor-set>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
<D:response>
<D:href>/his/23/ver/V2</D:href>
<D:propstat>
<D:prop>
<D:version-name>V2</D:version-name>
<D:creator-displayname>Fred</D:creator-displayname>
<D:successor-set/>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>
"""

RESPONSE = """\
<?xml version="1.0" encoding="utf-8"?>
<D:response xmlns:D="DAV:" xmlns:dc="DC:">
<D:href>/3/38/38f/38fa476aa97a4b2baeb41a481fdca00b</D:href>
<D:propstat>
<D:prop>
<D:getetag>6ca7-364-475e65375ce80</D:getetag>
<dc:created/>
<dc:resource/>
<dc:author>Me</dc:author>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
"""

LOCKDISCOVERY = """\
<?xml version="1.0" encoding="utf-8" ?>
<D:prop xmlns:D="DAV:">
<D:lockdiscovery>
<D:activelock>
<D:locktype><D:write/></D:locktype>
<D:lockscope><D:exclusive/></D:lockscope>
<D:depth>Infinity</D:depth>
<D:owner>
<D:href>
http://localhost/me.html
</D:href>
</D:owner>
<D:timeout>Second-604800</D:timeout>
<D:locktoken>
<D:href>
opaquelocktoken:e71d4fae-5dec-22d6-fea5-00a0c91e6be4
</D:href>
</D:locktoken>
</D:activelock>
</D:lockdiscovery>
</D:prop>
"""


class HTTPClientTestCase(unittest.TestCase):
    """Test the HTTPClient class."""
    def setUp(self):
        """Setup the client."""
        self.http = HTTPClient("127.0.0.1", 80)
        self.con = Mock.HTTPConnection()
        self.http._getconnection = lambda: self.con

    def test_init(self):
        """Test initializing the HTTPClient."""
        self.assertEqual(self.http.host, "127.0.0.1")
        self.assertEqual(self.http.port, 80)

    def test_getconnection(self):
        """Test HTTPClient._getconnection."""
        # http
        http = HTTPClient("127.0.0.1", 80)
        con = http._getconnection()
        self.assertTrue(isinstance(con, httplib.HTTPConnection))
        # https
        http = HTTPClient("127.0.0.1", 80, protocol="https")
        con = http._getconnection()
        self.assertTrue(isinstance(con, httplib.HTTPSConnection))


        http = HTTPClient("127.0.0.1", timeout=300, source_address="here.loc")
        # Python2.5
        mockhttplib = Mock.Omnivore(HTTPConnection=[None])
        context = dict(
            PYTHON2_6=False,
            PYTHON2_7=False,
            httplib=mockhttplib,
        )
        with injected(http._getconnection, **context):
            http._getconnection()
            call_log = mockhttplib.called["HTTPConnection"][0][1]
            self.assertFalse(call_log["strict"])
            self.assertEqual(call_log.get("timeout"), None)
            self.assertEqual(call_log.get("source_address"), None)
        # Python2.6
        mockhttplib = Mock.Omnivore(HTTPConnection=[None])
        context = dict(
            PYTHON2_6=True,
            PYTHON2_7=False,
            httplib=mockhttplib,
        )
        with injected(http._getconnection, **context):
            http._getconnection()
            call_log = mockhttplib.called["HTTPConnection"][0][1]
            self.assertFalse(call_log["strict"])
            self.assertEqual(call_log["timeout"], 300)
            self.assertEqual(call_log.get("source_address"), None)
        # Python2.7
        mockhttplib = Mock.Omnivore(HTTPConnection=[None])
        context = dict(
            PYTHON2_6=True,
            PYTHON2_7=True,
            httplib=mockhttplib,
        )
        with injected(http._getconnection, **context):
            http._getconnection()
            call_log = mockhttplib.called["HTTPConnection"][0][1]
            self.assertFalse(call_log["strict"])
            self.assertEqual(call_log["timeout"], 300)
            self.assertEqual(call_log.get("source_address"), "here.loc")

    def test_request(self):
        """Test HTTPClient._request."""
        headers = {"X-Test": "Hello"}
        resp = self.http._request("POST", "/foo", "my content", headers)
        self.assertEqual(resp, 200)
        # relative path to absolute path
        resp = self.http._request("POST", "foo", "my content", headers)
        self.assertTrue(self.con.path.startswith("/"))
        self.assertEqual(resp, 200)
        # cookies
        self.http.cookie = Mock.Omnivore()
        resp = self.http._request("POST", "/foo", "my content", headers)
        self.assertTrue("add_cookie_header" in self.http.cookie.called)
        # errors
        self.con.response.status = 400
        self.assertRaises(HTTPUserError, self.http._request, "POST", "/foo")
        self.con.response.status = 500
        self.assertRaises(HTTPServerError, self.http._request, "POST", "/foo")

    def test_setcookie(self):
        """Test HTTPClient.setcookie."""
        self.http.setcookie(CookieJar())
        self.assertTrue(isinstance(self.http.cookie, CookieJar))

    def test_setssl(self):
        """Test HTTPClient.setssl."""
        # set nothing
        self.http.setssl(None, None)
        self.assertEqual(self.http.protocol, "http")
        self.assertEqual(self.http.key_file, None)
        self.assertEqual(self.http.cert_file, None)
        # set key file only
        self.http.setssl("Foo", None)
        self.assertEqual(self.http.protocol, "https")
        self.assertEqual(self.http.key_file, "Foo")
        self.assertEqual(self.http.cert_file, None)
        self.http.protocol = "http"
        self.http.key_file = None
        # set cert file only
        self.http.setssl(None, "Foo")
        self.assertEqual(self.http.protocol, "https")
        self.assertEqual(self.http.key_file, None)
        self.assertEqual(self.http.cert_file, "Foo")
        self.http.protocol = "http"
        self.http.key_file = None
        # set key file and cert file
        self.http.setssl("Foo", "Bar")
        self.assertEqual(self.http.protocol, "https")
        self.assertEqual(self.http.key_file, "Foo")
        self.assertEqual(self.http.cert_file, "Bar")

    def test_prepare(self):
        """Test HTTPClient._prepare."""
        headers = {"X-Test": "Hello", "X-Test-2": "Umlaut ä"}
        query = {"foo": "bär"}
        http = HTTPClient("127.0.0.1", 80)
        http.setbasicauth("me", "secret")
        (uri, headers) = http._prepare("/foo bar/baz", headers, query)
        self.assertEqual(uri, "/foo%20bar/baz?foo=b%C3%A4r")
        expect = {
            'Authorization': 'Basic bWU6c2VjcmV0',
            'X-Test': 'Hello',
            'X-Test-2': '=?utf-8?b?VW1sYXV0IMOk?=',
        }
        self.assertEqual(headers, expect)

    def test_get(self):
        """Test HTTPClient.get."""
        # prepare mock connection
        self.con.response.status = 200
        query = {"path": "/foo/bar"}
        self.assertEqual(self.http.get("/index", None, query=query), 200)
        self.assertEqual(self.con.method, "GET")
        self.assertEqual(self.con.path, "/index?path=%2Ffoo%2Fbar")
        self.assertTrue(self.con.closed)

    def test_post(self):
        """Test HTTPClient.post."""
        data = StringIO("Test data")
        # prepare mock connection
        self.con.response.status = 200
        query = {"path": "/foo/bar"}
        self.assertEqual(self.http.post("/index", None, query=query), 200)
        self.assertEqual(self.con.method, "POST")
        self.assertEqual(self.con.path, "/index?path=%2Ffoo%2Fbar")
        self.assertTrue(self.con.closed)

    def test_post_py25(self):
        """Test HTTPClient.post with Python 2.5."""
        data = StringIO("Test data")
        # prepare mock connection
        self.con.response.status = 200
        query = {"path": "/foo/bar"}
        with injected(self.http.post, PYTHON2_6=False):
            self.assertEqual(self.http.post("/index", data), 200)
            self.assertEqual(self.con.method, "POST")
            self.assertEqual(self.con.path, "/index")
            self.assertTrue(self.con.closed)

    def test_post_content_none(self):
        """Test HTTPClient.post with None as content."""
        # prepare mock connection
        self.con.response.status = 200
        query = {"path": "/foo/bar"}
        self.assertEqual(self.http.post("/index", None, query=query), 200)
        self.assertEqual(self.con.method, "POST")
        self.assertEqual(self.con.path, "/index?path=%2Ffoo%2Fbar")
        self.assertTrue(self.con.closed)

    def test_post_no_query(self):
        """Test HTTPClient.post without query string."""
        data = StringIO("Test data")
        # prepare mock connection
        self.con.response.status = 200
        self.assertEqual(self.http.post("/index", data), 200)
        self.assertEqual(self.con.method, "POST")
        self.assertEqual(self.con.path, "/index")
        self.assertTrue(self.con.closed)

    def test_post_form_data(self):
        """Test HTTPClient.post form-data."""
        data = dict(a="foo", b="bar")
        def urlencode(data):
            urlencode.count += 1
            return urllib.urlencode(data)
        urlencode.count = 0
        # prepare mock connection
        mockurllib = Mock.Omnivore()
        mockurllib.quote = urllib.quote
        mockurllib.urlencode = urlencode
        context = dict(
            urllib_quote=mockurllib.quote,
            urllib_urlencode=mockurllib.urlencode,
        )        
        with injected(self.http.post, **context):
            resp = self.http.post("/index", data)
            self.assertEqual(urlencode.count, 1)
            self.assertEqual(resp, 200)

    def test_post_multipart(self):
        """Test HTTPClient.post multipart/form-data."""
        data = dict(a="foo", b="bar")
        resp = self.http.post("/index", data, as_multipart=True)
        self.assertEqual(resp, 200)
        self.assertEqual(self.con.method, "POST")
        self.assertEqual(self.con.path, "/index")
        self.assertTrue(self.con.closed)

    def test_options(self):
        """Test HTTPClient.options."""
        self.con.response.status = 200
        self.assertEqual(self.http.options("/index"), 200)
        self.assertEqual(self.con.method, "OPTIONS")
        self.assertEqual(self.con.path, "/index")
        self.assertTrue(self.con.closed)

    def test_head(self):
        """Test HTTPClient.head."""
        self.con.response.status = 200
        self.assertEqual(self.http.head("/index"), 200)
        self.assertEqual(self.con.method, "HEAD")
        self.assertEqual(self.con.path, "/index")
        self.assertTrue(self.con.closed)

    def test_delete(self):
        """Test HTTPClient.delete."""
        self.con.response.status = 200
        self.assertEqual(self.http.delete("/index"), 200)
        self.assertEqual(self.con.method, "DELETE")
        self.assertEqual(self.con.path, "/index")
        self.assertTrue(self.con.closed)

    def test_trace(self):
        """Test HTTPClient.trace."""
        self.con.response.status = 200
        self.assertEqual(self.http.trace("/index"), 200)
        self.assertEqual(self.con.method, "TRACE")
        self.assertEqual(self.con.path, "/index")
        self.assertTrue(self.con.closed)

    def test_trace_maxforwards_via(self):
        """Test HTTPClient.trace with given maxforwards and via."""
        self.con.response.status = 200
        self.assertEqual(self.http.trace("/index", 5, ["a", "b"]), 200)
        self.assertEqual(self.con.method, "TRACE")
        self.assertEqual(self.con.path, "/index")
        self.assertEqual(self.con.headers.get("Max-Forwards"), "5")
        self.assertEqual(self.con.headers.get("Via"), "a, b")
        self.assertTrue(self.con.closed)

    def test_connect(self):
        """Test HTTPClient.connect."""
        self.con.response.status = 200
        self.assertEqual(self.http.connect("/"), 200)
        self.assertEqual(self.con.method, "CONNECT")
        self.assertEqual(self.con.path, "/")
        self.assertTrue(self.con.closed)


class CoreWebDAVClientTestCase(unittest.TestCase):
    """Test the CoreWebDAVClient class."""
    def setUp(self):
        """Setup the client."""
        self.dav = CoreWebDAVClient("127.0.0.1", 80)
        self.dav.setbasicauth("test", "passwd")
        self.con = Mock.HTTPConnection()
        self.dav._getconnection = lambda: self.con
        response = Mock.Response()
        response.content = LOCKDISCOVERY
        response.status = 200
        self.lock = WebDAVLockResponse(self.dav, "/", response)

    def test_preparecopymove(self):
        """Test CoreWebDAVClient._preparecopymove."""
        source = "/foo bar/baz"
        dest = "/dest/in/ation"
        headers = {"X-Test": "Hello", "X-Test-2": "Umlaut ä"}
        query = {"foo": "bär"}
        http = CoreWebDAVClient("127.0.0.1", 80)
        http.setbasicauth("me", "secret")
        (source, headers) = http._preparecopymove(source, dest, 0,
                                                  False, headers)
        self.assertEqual(source, "/foo%20bar/baz")
        exp_headers = {
            "Destination": "http://127.0.0.1:80/dest/in/ation",
            "Overwrite": "F",
            "Authorization": "Basic bWU6c2VjcmV0",
            "X-Test": "Hello",
            "X-Test-2": "=?utf-8?b?VW1sYXV0IMOk?=",
        }
        self.assertEqual(headers, exp_headers)

    def test_preparecopymove_col(self):
        """Test CoreWebDAVClient._preparecopymove with collection as source."""
        source = "/foo bar/baz/"
        dest = "/dest/in/ation"
        headers = {"X-Test": "Hello", "X-Test-2": "Umlaut ä"}
        query = {"foo": "bär"}
        http = CoreWebDAVClient("127.0.0.1", 80)
        http.setbasicauth("me", "secret")
        (source, headers) = http._preparecopymove(source, dest, 0,
                                                  True, headers)
        self.assertEqual(source, "/foo%20bar/baz/")
        exp_headers = {
            "Destination": "http://127.0.0.1:80/dest/in/ation",
            "Depth": "0",
            "Overwrite": "T",
            "Authorization": "Basic bWU6c2VjcmV0",
            "X-Test": "Hello",
            "X-Test-2": "=?utf-8?b?VW1sYXV0IMOk?=",
        }
        self.assertEqual(headers, exp_headers)

    def test_preparecopymove_illegal_depth(self):
        """Test CoreWebDAVClient._preparecopymove with illegal depth value."""
        source = "/foo bar/baz"
        dest = "/dest/in/ation"
        headers = {"X-Test": "Hello"}
        query = {"foo": "bär"}
        http = CoreWebDAVClient("127.0.0.1", 80)
        http.setbasicauth("me", "secret")
        self.assertRaises(
            ValueError,
            http._preparecopymove,
            source, dest, "1", False, headers
        )

    def test_mkcol(self):
        """Test CoreWebDAVClient.mkcol."""
        # prepare mock connection
        self.con.response.status = 201
        self.assertEqual(self.dav.mkcol("/foobar"), 201)
        self.assertEqual(self.con.method, "MKCOL")
        self.assertEqual(self.con.path, "/foobar")
        self.assertTrue(self.con.closed)
        self.assertTrue("Authorization" in self.con.headers)

    def test_propfind(self):
        """Test CoreWebDAVClient.propfind."""
        # prepare mock connection
        self.con.response.status = 207
        self.con.response.content = MULTISTATUS
        self.assertEqual(self.dav.propfind("/foobar"), 207)
        self.assertEqual(self.con.method, "PROPFIND")
        self.assertEqual(self.con.path, "/foobar")
        self.assertEqual(self.con.headers["Depth"], "0")
        self.assertTrue(self.con.closed)
        self.assertTrue("Authorization" in self.con.headers)

    def test_propfind_depth_1(self):
        """Test CoreWebDAVClient.propfind with depth 1."""
        # prepare mock connection
        self.con.response.status = 207
        self.con.response.content = MULTISTATUS
        self.assertEqual(self.dav.propfind("/foobar", "1"), 207)
        self.assertEqual(self.con.method, "PROPFIND")
        self.assertEqual(self.con.path, "/foobar")
        self.assertEqual(self.con.headers["Depth"], "1")
        self.assertTrue(self.con.closed)
        self.assertTrue("Authorization" in self.con.headers)

    def test_propfind_illegal_depth(self):
        """Test CoreWebDAVClient.propfind with illegal depth."""
        # prepare mock connection
        self.assertRaises(ValueError, self.dav.propfind, "/foobar", "ABC")

    def test_propfind_illegal_args(self):
        """Test CoreWebDAVClient.propfind with illegal args."""
        # prepare mock connection
        self.assertRaises(ValueError,
                          self.dav.propfind, "/foobar", 1,
                          properties=["foo"], include=["bar"])

    def test_put(self):
        """Test CoreWebDAVClient.put."""
        # prepare mock connection
        self.con.response.status = 201
        self.con.response.content = "Test content."
        self.assertEqual(self.dav.put("/foobar", self.con.response), 201)
        self.assertEqual(self.con.method, "PUT")
        self.assertEqual(self.con.path, "/foobar")
        if PYTHONVERSION == (2, 5):
            self.assertEqual(self.con.body, "Test content.")
        else:
            self.assertEqual(self.con.body, self.con.response)
        self.assertTrue(self.con.closed)
        self.assertTrue("Authorization" in self.con.headers)

    def test_proppatch(self):
        """Test CoreWebDAVClient.proppatch."""
        self.con.response.status = 207
        self.con.response.content = MULTISTATUS
        props = {"CADN:author": "me", "CADN:created": "2009-09-09 13:31"}
        ns = {"CADN": "CADN:"}
        self.assertEqual(207, self.dav.proppatch("/foobar", props, None, ns))

    def test_proppatch_noprops(self):
        """Test CoreWebDAVClient.proppatch with no defined properties."""
        ns = {"CADN": "CADN:"}
        self.assertRaises(ValueError,
                          self.dav.proppatch, "/foobar", None, None, ns)

    def test_delete(self):
        """Test CoreWebDAVClient.delete."""
        self.con.response.status = 200
        self.assertEqual(200, self.dav.delete("/foobar", None))

    def test_delete_collection(self):
        """Test CoreWebDAVClient.delete on collection."""
        self.con.response.status = 200
        self.assertEqual(200, self.dav.delete("/foobar/", None))

    def test_copy(self):
        """Test CoreWebDAVClient.copy."""
        self.con.response.status = 200
        source = "/foo bar/baz"
        dest = "/dest/in/ation"
        headers = {"X-Test": "Hello"}
        resp = self.dav.copy(source, dest, 0, False, headers)
        self.assertEqual(resp, 200)

    def test_move(self):
        """Test CoreWebDAVClient.move."""
        self.con.response.status = 200
        source = "/foo bar/baz"
        dest = "/dest/in/ation"
        headers = {"X-Test": "Hello"}
        resp = self.dav.move(source, dest, 0, False, headers)
        self.assertEqual(resp, 200)

    def test_move_collection_illegal_depth(self):
        """Test CoreWebDAVClient.move on collections with illegal depth."""
        self.con.response.status = 200
        source = "/foo bar/baz/"
        dest = "/dest/in/ation"
        headers = {"X-Test": "Hello"}
        self.assertRaises(
            ValueError,
            self.dav.move,
            source, dest, 0
        )

    def test_lock(self):
        """Test CoreWebDAVClient.lock."""
        self.con.response.status = 200
        resp = self.dav.lock("/foo")
        self.assertTrue(isinstance(resp, WebDAVLockResponse))
        self.assertEqual(resp, 200)

    def test_lock_timeout(self):
        """Test CoreWebDAVClient.lock with timeout."""
        self.con.response.status = 200
        resp = self.dav.lock("/foo", timeout=12345)
        self.assertEqual(resp, 200)

    def test_lock_timeout_inf(self):
        """Test CoreWebDAVClient.lock with infinite timeout."""
        self.con.response.status = 200
        resp = self.dav.lock("/foo", timeout="infinite")
        self.assertEqual(resp, 200)

    def test_lock_timeout_toolong(self):
        """Test CoreWebDAVClient.lock with too long timeout."""
        self.assertRaises(
            ValueError,
            self.dav.lock,
            "/foo",
            timeout=4294967296
        )

    def test_lock_timeout_err(self):
        """Test CoreWebDAVClient.lock with wrong timeout."""
        self.assertRaises(
            ValueError,
            self.dav.lock,
            "/foo",
            timeout="abc"
        )

    def test_lock_depth(self):
        """Test CoreWebDAVClient.lock with given depth."""
        self.con.response.status = 200
        resp = self.dav.lock("/foo", depth=0)
        self.assertEqual(resp, 200)
        self.assertEqual(self.con.headers["Depth"], "0")

    def test_lock_illegaldepth(self):
        """Test CoreWebDAVClient.lock with given illegal depth."""
        self.assertRaises(
            ValueError,
            self.dav.lock,
            "/foo",
            depth=1
        )

    def test_unlock_lock(self):
        """Test CoreWebDAVClient.unlock with lock object."""
        self.dav.locks[self.lock._tag] = self.lock
        self.con.response.status = 204
        resp = self.dav.unlock(self.lock)
        self.assertEqual(self.con.method, "UNLOCK")
        self.assertEqual(self.con.headers["Lock-Token"],
                         "<%s>" % self.lock.locktokens[0])
        self.assertTrue(self.lock._tag not in self.dav.locks)

    def test_unlock_uri(self):
        """Test CoreWebDAVClient.unlock with uri."""
        self.dav.locks[self.lock._tag] = self.lock
        self.con.response.status = 204
        resp = self.dav.unlock("/")
        self.assertEqual(self.con.method, "UNLOCK")
        self.assertEqual(self.con.headers["Lock-Token"],
                         "<%s>" % self.lock.locktokens[0])
        self.assertTrue(self.lock._tag not in self.dav.locks)

    def test_unlock_uri_no_token(self):
        """Test CoreWebDAVClient.unlock with uri."""
        self.con.response.status = 204
        self.assertRaises(ValueError, self.dav.unlock, "/")

    def test_unlock_lock_no_token(self):
        """Test CoreWebDAVClient.unlock with lock object and no token."""
        self.con.response.status = 204
        resp = self.dav.unlock(self.lock)
        self.assertEqual(self.con.method, "UNLOCK")
        self.assertEqual(self.con.headers["Lock-Token"],
                         "<%s>" % self.lock.locktokens[0])
        self.assertTrue(self.lock._tag not in self.dav.locks)


class ExtendedWebDAVClientTestCase(unittest.TestCase):
    """Test the ExtendedWebDAVClient class."""
    def setUp(self):
        """Setup the client."""
        self.dav = ExtendedWebDAVClient("127.0.0.1", 80)
        self.dav.setbasicauth("test", "passwd")
        self.con = Mock.HTTPConnection()
        self.dav._getconnection = lambda: self.con

    def test_report(self):
        """Test ExtendedWebDAVClient.report."""
        self.con.response.status = 207
        self.con.response.content = REPORT
        props = ["version-name", "creator-displayname", "successor-set"]
        response = self.dav.report("/foo.html", properties=props)
        self.assertEqual(response, 207)
        self.assertEqual(self.con.method, "REPORT")
        self.assertEqual(self.con.path, "/foo.html")
        self.assertEqual(self.con.headers["Depth"], "0")
        self.assertTrue(self.con.closed)
        self.assertTrue("Authorization" in self.con.headers)

    def test_report_depth_1(self):
        """Test ExtendedWebDAVClient.report with depth 1."""
        self.con.response.status = 207
        self.con.response.content = REPORT
        props = ["version-name", "creator-displayname", "successor-set"]
        response = self.dav.report("/foo.html", "1", props)
        self.assertEqual(response, 207)
        self.assertEqual(self.con.method, "REPORT")
        self.assertEqual(self.con.path, "/foo.html")
        self.assertEqual(self.con.headers["Depth"], "1")
        self.assertTrue(self.con.closed)
        self.assertTrue("Authorization" in self.con.headers)

    def test_report_illegal_depth(self):
        """Test ExtendedWebDAVClient.report with illegal depth."""
        # prepare mock connection
        self.assertRaises(ValueError, self.dav.report, "/foo.html", "ABC")


class HTTPResponseTestCase(unittest.TestCase):
    """Test HTTPResponse class."""
    def setUp(self):
        """Initialize the tests."""
        self.response = Mock.Response()
        self.response.status = 207
        self.response.content = MULTISTATUS
        self.httpresponse = HTTPResponse(self.response)
        # 401
        self.response = Mock.Response()
        digest = 'Digest realm="restricted" domain="foo.de" nonce="abcd1234"'\
                 'opaque="qwer4321" stale=false algorithm="MD5"'
        self.response.headers["www-authenticate"] = digest
        self.response.status = 401
        self.response.content = ""
        self.httpresponse401 = HTTPResponse(self.response)

    def test_init(self):
        """Test Initializing the HTTPResponse."""
        self.assertEqual(self.httpresponse.content, MULTISTATUS)
        self.assertEqual(self.httpresponse.statusline,
                         "HTTP/1.1 207 The reason")
        self.assertEqual(self.httpresponse401.content, "")
        self.assertEqual(self.httpresponse401.statusline,
                         "HTTP/1.1 401 The reason")
        self.assertEqual(self.httpresponse401.schema, "Digest")
        self.assertEqual(self.httpresponse401.realm, "restricted")
        self.assertEqual(self.httpresponse401.domain, "foo.de")
        self.assertEqual(self.httpresponse401.nonce, "abcd1234")
        self.assertEqual(self.httpresponse401.opaque, "qwer4321")
        self.assertFalse(self.httpresponse401.stale)
        self.assertEqual(self.httpresponse401.algorithm, hashlib.md5)

    def test_str(self):
        """Test HTTPResponse.__str__."""
        self.assertEqual(str(self.httpresponse), "HTTP/1.1 207 The reason")
        self.assertEqual(str(self.httpresponse401), "HTTP/1.1 401 The reason")

    def test_repr(self):
        """Test HTTPResponse.__repr__."""
        self.assertEqual(repr(self.httpresponse), "<HTTPResponse: 207>")
        self.assertEqual(repr(self.httpresponse401), "<HTTPResponse: 401>")

    def test_status(self):
        """Test HTTPResponse.status property."""
        self.assertEqual(self.httpresponse, 207)
        self.assertEqual(self.httpresponse401, 401)


class WebDAVResponseTestCase(unittest.TestCase):
    """Test the WebDAVResponse class."""
    def test_init(self):
        """Test initializing the WebDAVResponse."""
        response = Mock.Response()
        response.content = MULTISTATUS
        # no parsing
        response.status = 200
        davresponse = WebDAVResponse(response)
        self.assertFalse(bool(davresponse._etree.getroot()))
        # parsing
        response.status = 207
        davresponse = WebDAVResponse(response)
        self.assertTrue(bool(davresponse._etree.getroot()))
        # broken xml
        response.status = 207
        response.content = MULTISTATUS_BROKEN
        davresponse = WebDAVResponse(response)
        self.assertTrue(bool(davresponse._etree.getroot()))
        self.assertTrue(isinstance(davresponse.parse_error, ParseError))

    def test_len(self):
        """Test WebDAVResponse.__len__."""
        response = Mock.Response()
        response.content = MULTISTATUS
        response.status = 200
        davresponse = WebDAVResponse(response)
        self.assertEqual(len(davresponse), 1)

    def test_len_207(self):
        """Test WebDAVResponse.__len__ in Multi-Status."""
        response = Mock.Response()
        response.content = MULTISTATUS
        response.status = 207
        davresponse = WebDAVResponse(response)
        self.assertEqual(len(davresponse), 1)

    def test_iter(self):
        """Test WebDAVResponse.__iter__."""
        response = Mock.Response()
        response.content = MULTISTATUS
        response.status = 200
        davresponse = WebDAVResponse(response)
        self.assertTrue(isinstance(list(davresponse)[0], WebDAVResponse))

    def test_iter_207(self):
        """Test WebDAVResponse.__iter__ in Multi-Status."""
        response = Mock.Response()
        response.content = MULTISTATUS
        response.status = 207
        davresponse = WebDAVResponse(response)
        self.assertEqual(list(davresponse)[0], 200)

    def test_parse_xml_content(self):
        """Test WebDAVResponse._parse_xml_content."""
        response = Mock.Response()
        response.content = MULTISTATUS
        response.status = 207
        with replaced(WebDAVResponse, _parse_xml_content=Mock.omnivore_func()):
            davresponse = WebDAVResponse(response)
        davresponse._parse_xml_content()
        href = davresponse._etree.findtext("/{DAV:}response/{DAV:}href")
        self.assertEquals(href, "/3/38/38f/38fa476aa97a4b2baeb41a481fdca00b")

    def test_parse_xml_content_broken(self):
        """Test WebDAVResponse._parse_xml_content with broken XML."""
        response = Mock.Response()
        response.content = MULTISTATUS_BROKEN
        response.status = 207
        with replaced(WebDAVResponse, _parse_xml_content=Mock.omnivore_func()):
            davresponse = WebDAVResponse(response)
        davresponse._parse_xml_content()
        empty = davresponse._etree.getroot().getchildren()[0]
        self.assertEquals(empty.tag, "empty")

    def test_set_multistatus(self):
        """Test WebDAVResponse._set_multistatus."""
        response = Mock.Response()
        response.content = MULTISTATUS
        response.status = 200
        davresponse = WebDAVResponse(response)
        mockparser = Mock.Omnivore()
        with replaced(davresponse, _parse_xml_content=mockparser):
            self.assertFalse(davresponse.is_multistatus)
            self.assertEquals(len(mockparser.called["__call__"]), 0)
            davresponse._set_multistatus()
            self.assertTrue(davresponse.is_multistatus)
            self.assertEquals(len(mockparser.called["__call__"]), 1)


class WebDAVLockResponseTestCase(unittest.TestCase):
    """Test the WebDAVLockResponse class."""
    def setUp(self):
        """Setup the tests"""
        self.client = CoreWebDAVClient("localhost")
        response = Mock.Response()
        response.content = LOCKDISCOVERY
        response.status = 200
        self.lock = WebDAVLockResponse(self.client, "/", response)

    def test_init_200(self):
        """Test WebDAVLockResponse.__init__ with 200 status."""
        lock = self.lock
        self.assertEqual(lock.lockscope.tag, "{DAV:}exclusive")
        self.assertEqual(lock.locktype.tag, "{DAV:}write")
        self.assertEqual(lock.depth, "Infinity")
        href = "http://localhost/me.html"
        self.assertEqual(lock.owner.findtext("{DAV:}href").strip(), href)
        self.assertEqual(lock.timeout, "Second-604800")
        token = "opaquelocktoken:e71d4fae-5dec-22d6-fea5-00a0c91e6be4"
        self.assertEqual(lock.locktokens[0], token)

    def test_init_409(self):
        """Test WebDAVLockResponse.__init__ with 409 status."""
        client = CoreWebDAVClient("localhost")
        response = Mock.Response()
        response.content = MULTISTATUS
        response.status = 409
        lock = WebDAVLockResponse(client, "/", response)
        self.assertTrue(lock._etree.find("/{DAV:}response") is not None)
        self.assertTrue(lock.is_multistatus)

    def test_repr(self):
        """Test WebDAVLockResponse.__repr__."""
        lrepr = "<WebDAVLockResponse: <%s> 200>" % self.lock._tag
        self.assertEqual(repr(self.lock), lrepr)

    def test_call(self):
        """Test WebDAVLockResponse.__call__."""
        self.assertTrue(self.lock._tagged)
        self.lock(False)
        self.assertFalse(self.lock._tagged)
        self.lock()
        self.assertTrue(self.lock._tagged)
        self.lock(False)
        self.lock(True)
        self.assertTrue(self.lock._tagged)

    def test_contextmanager(self):
        """Test contextmanager on WebDAVLockResponse."""
        self.client.headers["If"] = "My previous if"
        # tagged
        with self.lock:
            expect = "<http://localhost:80/> "\
                     "(<opaquelocktoken:e71d4fae-5dec-22d6-fea5-00a0c91e6be4>)"
            if_header = self.client.headers["If"]
            self.assertEqual(expect, if_header)
        self.assertEqual("My previous if", self.client.headers["If"])
        # untagged
        with self.lock(False):
            expect = "(<opaquelocktoken:e71d4fae-5dec-22d6-fea5-00a0c91e6be4>)"
            if_header = self.client.headers["If"]
            self.assertEqual(expect, if_header)
        self.assertEqual("My previous if", self.client.headers["If"])
        # untagged, no previous if header
        del self.client.headers["If"]
        with self.lock(False):
            expect = "(<opaquelocktoken:e71d4fae-5dec-22d6-fea5-00a0c91e6be4>)"
            if_header = self.client.headers["If"]
            self.assertEqual(expect, if_header)
        self.assertTrue("If" not in self.client.headers)


class MultiStatusResponseTestCase(unittest.TestCase):
    """Test the MultiStatusResponse class."""
    def setUp(self):
        self.etree = ElementTree()
        self.etree.parse(StringIO(RESPONSE))
        self.msr = MultiStatusResponse(self.etree.getroot())

    def test_init(self):
        """Test initializing the MultiStatusResponse."""
        self.assertEqual(self.msr, 200)

    def test_repr(self):
        """Test MultiStatusResponse.__repr__."""
        self.assertEqual(repr(self.msr), "<MultiStatusResponse: 200>")

    def test_getitem(self):
        """Test MultiStatusResponse.__getitem__."""
        self.assertEqual(self.msr["getetag"].text, "6ca7-364-475e65375ce80")
        self.assertEqual(self.msr["{DC:}author"].text, "Me")
        self.assertRaises(KeyError, lambda: self.msr['non-existant'])

    def test_keys(self):
        """Test MultiStatusResponse.keys."""
        expect = ['getetag', '{DC:}created', '{DC:}resource', '{DC:}author']
        expect.sort()
        keys = self.msr.keys()
        keys.sort()
        self.assertEqual(keys, expect)

    def test_iter(self):
        """Test MultiStatusResponse.__iter__."""
        expect = ['getetag', '{DC:}created', '{DC:}resource', '{DC:}author']
        expect.sort()
        keys = list(self.msr)
        keys.sort()
        self.assertEqual(keys, expect)

    def test_iterkeys(self):
        """Test MultiStatusResponse.iterkeys."""
        expect = ['getetag', '{DC:}created', '{DC:}resource', '{DC:}author']
        expect.sort()
        keys = list(self.msr.iterkeys())
        keys.sort()
        self.assertEqual(keys, expect)

    def test_items(self):
        """Test MultiStatusResponse.items."""
        expect = [('getetag', '6ca7-364-475e65375ce80'),
                  ('{DC:}created', None),
                  ('{DC:}resource', None),
                  ('{DC:}author', 'Me')]
        expect.sort()
        items = list((k, v.text) for (k, v) in self.msr.items())
        items.sort()
        self.assertEqual(items, expect)

    def test_iteritems(self):
        """Test MultiStatusResponse.iteritems."""
        expect = [('getetag', '6ca7-364-475e65375ce80'),
                  ('{DC:}created', None),
                  ('{DC:}resource', None),
                  ('{DC:}author', 'Me')]
        expect.sort()
        items = list((k, v.text) for (k, v) in self.msr.iteritems())
        items.sort()
        self.assertEqual(items, expect)

    def test_get(self):
        """Test MultiStatusResponse.get."""
        self.assertEqual(self.msr.get("{DC:}author").text, "Me")
        self.assertEqual(self.msr.get("author", namespace="DC:").text, "Me")
        self.assertEqual(self.msr.get("non-existant", "You"), "You")

    def test_statusline(self):
        """Test MultiStatusResponse.statusline property."""
        self.assertEqual(self.msr.statusline, "HTTP/1.1 200 OK")

    def test_href(self):
        """Test MultiStatusResponse.href property."""
        self.assertEqual(self.msr.href,
                         "/3/38/38f/38fa476aa97a4b2baeb41a481fdca00b")

    def test_namespaces(self):
        """Test MultiStatusResponse.namespaces property."""
        expect = set(["DC:", "DAV:"])
        self.msr.iterkeys = lambda b: ["foo", "bar", "{DC:}x", "{DAV:}y"]
        self.assertEqual(self.msr.namespaces, expect)
