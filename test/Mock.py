# Mock object for unittests.
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
"""Mock object for unittests."""

from collections import defaultdict
from contextlib import contextmanager
from email.mime.multipart import MIMEMultipart
from functools import partial
from StringIO import StringIO
import urllib2


@contextmanager
def injected(func, **kwargs):
    """Inject vars into a function or method while in context mode."""
    # recognize methods
    if hasattr(func, "im_func"):
        func = func.im_func
    # save and replace current function globals as to kwargs
    func_globals = func.func_globals
    saved = dict((k, func_globals[k]) for k in kwargs if k in func_globals)
    func_globals.update(kwargs)
    # context is now ready to be used
    yield
    # restore previous state
    func_globals.update(saved)


@contextmanager
def replaced(obj, **attrs):
    """Replace attribute in object while in context mode."""
    # save and replace current attributes
    saved = dict((k, getattr(obj, k)) for k in attrs)
    for (name, attr) in attrs.iteritems():
        setattr(obj, name, attr)
    # context is ready
    yield
    # restore previous state
    for (name, attr) in saved.iteritems():
        setattr(obj, name, attr)


def omnivore_func(retval=None, exception=None):
    """Return a function accepting any number of args and act accordingly.

    retval -- Returned function returns this value on call.
    exception -- If not None, this will be raised by the returned function.

    """
    def omnivore(*args, **kwargs):
        omnivore.callcount += 1
        if exception is not None:
            raise exception
        return retval
    omnivore.callcount = 0
    return omnivore


class Omnivore(object):
    """Omnivore class.

    Return pre-defined values or raise predefined exceptions an any method
    that may be called, including __call__.

    """

    def __init__(self, **kwargs):
        """Initialize with return values.

        **kwargs -- Key is the method name, value is the returned value. If
                    the value is an instance of Exception, it will be raised.

        """
        self.__name__ = "Omnivore"
        self.retvals = dict()
        for (key, value) in kwargs.iteritems():
            self.retvals[key] = iter(value)
        self.called = defaultdict(list)

    def __enter__(self):
        self.called["__enter__"] = True
        return self

    def __exit__(exctype, excvalue, exctb):
        self.called["__exit__"] = (exctype, excvalue, exctb)

    def method(self, methodname, *args, **kwargs):
        self.called[methodname].append((args, kwargs))
        generator = self.retvals.get(methodname)
        if generator is None:
            return None
        value = generator.next()
        if isinstance(value, Exception):
            raise value
        return value

    def __getattr__(self, name):
        return partial(self.method, name)

    def __call__(self, *args, **kwargs):
        return self.method("__call__", *args, **kwargs)


class FakeMIMEMultipart(object):
    """Subclass of MIMEMultipart."""
    def __init__(self, boundary="foobar"):
        self.boundary = boundary

    def __call__(self, subtype):
        boundary = self.boundary
        if subtype == "mixed":
            boundary += "-mixed"
        return MIMEMultipart(subtype, boundary)


class HTTPConnection(object):
    """Mock httplib.HTTPConnection object."""

    def __init__(self):
        # input
        self.method = None
        self.path = None
        self.body = None
        self.headers = None
        # output
        self.response = Response()
        self.closed = False

    def request(self, method, path, body=None, headers=None):
        self.method = method
        self.path = path
        self.body = body
        self.headers = headers

    def __enter__(self):
        pass

    def __exit__(self, *args):
        pass

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class ModuleProxy(object):
    """Mock module. Must be instantiated."""

    def __init__(self, module):
        self.__module = module

    def __getattr__(self, name):
        return getattr(self.__module, name)


class Response(urllib2.HTTPError):
    """Mock urllib2 response object."""

    def __init__(self):
        self.code = None
        self.content = ""
        self.version = 11
        self.reason = "The reason"
        self.headers = dict()
        self.status = 200

    def getheaders(self):
        return self.headers

    def read(self):
        return self.content

