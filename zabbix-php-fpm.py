#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=W0622

# Copyright (c) 2006 Allan Saddi <allan@saddi.com>
# Copyright (c) 2011 Vladimir Rusinov <vladimir@greenmice.info>
# Copyright (c) 2016 gael p <gael@alfa-safety.fr>

# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Id$

from os import walk, path
import re
import json
import select
import struct
import socket
import errno
import types
import argparse

phpfpmdir = ['/etc/php-fpm53.d', '/etc/php-fpm54.d',
             '/etc/php-fpm55.d', '/etc/php-fpm56.d']
webmin_root = '/etc/webmin/virtual-server/domains'

CONFIGFILE = '/etc/as/zabbix-php-fpm.json'


__author__ = 'Allan Saddi <allan@saddi.com>'
__version__ = '$Revision$'


__all__ = ['FCGIApp']

# Constants from the spec.
FCGI_LISTENSOCK_FILENO = 0

FCGI_HEADER_LEN = 8

FCGI_VERSION_1 = 1

FCGI_BEGIN_REQUEST = 1
FCGI_ABORT_REQUEST = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_DATA = 8
FCGI_GET_VALUES = 9
FCGI_GET_VALUES_RESULT = 10
FCGI_UNKNOWN_TYPE = 11
FCGI_MAXTYPE = FCGI_UNKNOWN_TYPE

FCGI_NULL_REQUEST_ID = 0

FCGI_KEEP_CONN = 1

FCGI_RESPONDER = 1
FCGI_AUTHORIZER = 2
FCGI_FILTER = 3

FCGI_REQUEST_COMPLETE = 0
FCGI_CANT_MPX_CONN = 1
FCGI_OVERLOADED = 2
FCGI_UNKNOWN_ROLE = 3

FCGI_MAX_CONNS = 'FCGI_MAX_CONNS'
FCGI_MAX_REQS = 'FCGI_MAX_REQS'
FCGI_MPXS_CONNS = 'FCGI_MPXS_CONNS'

FCGI_Header = '!BBHHBx'
FCGI_BeginRequestBody = '!HB5x'
FCGI_EndRequestBody = '!LB3x'
FCGI_UnknownTypeBody = '!B7x'

FCGI_BeginRequestBody_LEN = struct.calcsize(FCGI_BeginRequestBody)
FCGI_EndRequestBody_LEN = struct.calcsize(FCGI_EndRequestBody)
FCGI_UnknownTypeBody_LEN = struct.calcsize(FCGI_UnknownTypeBody)

if __debug__:
    import time

    # Set non-zero to write debug output to a file.
    DEBUG = 0
    DEBUGLOG = '/tmp/fcgi_app.log'

    def _debug(level, msg):
        # pylint: disable=W0702
        if DEBUG < level:
            return

        try:
            f = open(DEBUGLOG, 'a')
            f.write('%sfcgi: %s\n' % (time.ctime()[4:-4], msg))
            f.close()
        except:
            pass


def decode_pair(s, pos=0):
    """
    Decodes a name/value pair.

    The number of bytes decoded as well as the name/value pair
    are returned.
    """
    nameLength = ord(s[pos])
    if nameLength & 128:
        nameLength = struct.unpack('!L', s[pos:pos + 4])[0] & 0x7fffffff
        pos += 4
    else:
        pos += 1

    valueLength = ord(s[pos])
    if valueLength & 128:
        valueLength = struct.unpack('!L', s[pos:pos + 4])[0] & 0x7fffffff
        pos += 4
    else:
        pos += 1

    name = s[pos:pos + nameLength]
    pos += nameLength
    value = s[pos:pos + valueLength]
    pos += valueLength

    return (pos, (name, value))


def encode_pair(name, value):
    """
    Encodes a name/value pair.

    The encoded string is returned.
    """
    nameLength = len(name)
    if nameLength < 128:
        s = chr(nameLength)
    else:
        s = struct.pack('!L', nameLength | 0x80000000L)

    valueLength = len(value)
    if valueLength < 128:
        s += chr(valueLength)
    else:
        s += struct.pack('!L', valueLength | 0x80000000L)

    return s + name + value


class Record(object):
    """
    A FastCGI Record.

    Used for encoding/decoding records.
    """

    def __init__(self, typ=FCGI_UNKNOWN_TYPE, requestId=FCGI_NULL_REQUEST_ID):
        self.version = FCGI_VERSION_1
        self.type = typ
        self.requestId = requestId
        self.contentLength = 0
        self.paddingLength = 0
        self.contentData = ''

    def _recvall(sock, length):
        """
        Attempts to receive length bytes from a socket, blocking if necessary.
        (Socket may be blocking or non-blocking.)
        """
        dataList = []
        recvLen = 0
        while length:
            try:
                data = sock.recv(length)
            except socket.error, e:
                if e[0] == errno.EAGAIN:
                    select.select([sock], [], [])
                    continue
                else:
                    raise
            if not data:  # EOF
                break
            dataList.append(data)
            dataLen = len(data)
            recvLen += dataLen
            length -= dataLen
        return ''.join(dataList), recvLen
    _recvall = staticmethod(_recvall)

    def read(self, sock):
        """Read and decode a Record from a socket."""
        try:
            header, length = self._recvall(sock, FCGI_HEADER_LEN)
        except:
            raise EOFError

        if length < FCGI_HEADER_LEN:
            raise EOFError

        self.version, self.type, self.requestId, self.contentLength, \
         self.paddingLength = struct.unpack(FCGI_Header, header)

        if __debug__:
            _debug(9, 'read: fd = %d, type = %d, requestId = %d, '
                   'contentLength = %d' %
                   (sock.fileno(), self.type, self.requestId,
                    self.contentLength))

        if self.contentLength:
            try:
                self.contentData, length = self._recvall(sock,
                                                         self.contentLength)
            except:
                raise EOFError

            if length < self.contentLength:
                raise EOFError

        if self.paddingLength:
            try:
                self._recvall(sock, self.paddingLength)
            except:
                raise EOFError

    def _sendall(sock, data):
        """
        Writes data to a socket and does not return until all the data is sent.
        """
        length = len(data)
        while length:
            try:
                sent = sock.send(data)
            except socket.error, e:
                if e[0] == errno.EAGAIN:
                    select.select([], [sock], [])
                    continue
                else:
                    raise
            data = data[sent:]
            length -= sent
    _sendall = staticmethod(_sendall)

    def write(self, sock):
        """Encode and write a Record to a socket."""
        self.paddingLength = - self.contentLength & 7

        if __debug__:
            _debug(9, 'write: fd = %d, type = %d, requestId = %d, '
                   'contentLength = %d' %
                   (sock.fileno(), self.type, self.requestId,
                    self.contentLength))

        header = struct.pack(FCGI_Header, self.version, self.type,
                             self.requestId, self.contentLength,
                             self.paddingLength)
        self._sendall(sock, header)
        if self.contentLength:
            self._sendall(sock, self.contentData)
        if self.paddingLength:
            self._sendall(sock, '\x00' * self.paddingLength)


class FCGIApp(object):

    def __init__(self, connect=None, host=None, port=None, filterEnviron=True):
        if host is not None:
            assert port is not None
            connect = (host, port)

        self._connect = connect
        self._filterEnviron = filterEnviron

    def __call__(self, environ, start_response=None):
        # For sanity's sake, we don't care about FCGI_MPXS_CONN
        # (connection multiplexing). For every request, we obtain a new
        # transport socket, perform the request, then discard the socket.
        # This is, I believe, how mod_fastcgi does things...

        sock = self._getConnection()

        # Since this is going to be the only request on this connection,
        # set the request ID to 1.
        requestId = 1

        # Begin the request
        rec = Record(FCGI_BEGIN_REQUEST, requestId)
        rec.contentData = struct.pack(FCGI_BeginRequestBody, FCGI_RESPONDER, 0)
        rec.contentLength = FCGI_BeginRequestBody_LEN
        rec.write(sock)

        # Filter WSGI environ and send it as FCGI_PARAMS
        if self._filterEnviron:
            params = self._defaultFilterEnviron(environ)
        else:
            params = self._lightFilterEnviron(environ)
        # TODO: Anything not from environ that needs to be sent also?
        self._fcgiParams(sock, requestId, params)
        self._fcgiParams(sock, requestId, {})

        # Transfer wsgi.input to FCGI_STDIN
        # content_length = int(environ.get('CONTENT_LENGTH') or 0)
        s = ''
        while True:

            rec = Record(FCGI_STDIN, requestId)
            rec.contentData = s
            rec.contentLength = len(s)
            rec.write(sock)
            if not s:
                break

        # Empty FCGI_DATA stream
        rec = Record(FCGI_DATA, requestId)
        rec.write(sock)

        # Main loop. Process FCGI_STDOUT, FCGI_STDERR, FCGI_END_REQUEST
        # records from the application.
        result = []
        err = ''
        while True:
            inrec = Record()
            inrec.read(sock)
            if inrec.type == FCGI_STDOUT:
                if inrec.contentData:
                    result.append(inrec.contentData)
                else:
                    # TODO: Should probably be pedantic and no longer
                    # accept FCGI_STDOUT records?"
                    pass
            elif inrec.type == FCGI_STDERR:
                # Simply forward to wsgi.errors
                err += inrec.contentData
            elif inrec.type == FCGI_END_REQUEST:
                # TODO: Process appStatus/protocolStatus fields?
                break

        # Done with this transport socket, close it. (FCGI_KEEP_CONN was not
        # set in the FCGI_BEGIN_REQUEST record we sent above. So the
        # application is expected to do the same.)
        sock.close()

        result = ''.join(result)

        # Parse response headers from FCGI_STDOUT
        status = '200 OK'
        headers = []
        pos = 0
        while True:
            eolpos = result.find('\n', pos)
            if eolpos < 0:
                break
            line = result[pos:eolpos - 1]
            pos = eolpos + 1

            # strip in case of CR. NB: This will also strip other
            # whitespace...
            line = line.strip()

            # Empty line signifies end of headers
            if not line:
                break

            # TODO: Better error handling
            header, value = line.split(':', 1)
            header = header.strip().lower()
            value = value.strip()

            if header == 'status':
                # Special handling of Status header
                status = value
                if status.find(' ') < 0:
                    # Append a dummy reason phrase if one was not provided
                    status += ' FCGIApp'
            else:
                headers.append((header, value))

        result = result[pos:]

        # Set WSGI status, headers, and return result.
        # start_response(status, headers)
        # return [result]

        return status, headers, result, err

    def _getConnection(self):
        if self._connect is not None:
            # The simple case. Create a socket and connect to the
            # application.
            if isinstance(self._connect, types.StringTypes):
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(self._connect)
            elif hasattr(socket, 'create_connection'):
                sock = socket.create_connection(self._connect)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(self._connect)
            return sock

        # To be done when I have more time...
        raise NotImplementedError(
            'Launching and managing FastCGI programs not yet implemented')

    def _fcgiGetValues(self, sock, vars):  # @ReservedAssignment
        # Construct FCGI_GET_VALUES record
        outrec = Record(FCGI_GET_VALUES)
        data = []
        for name in vars:
            data.append(encode_pair(name, ''))
        data = ''.join(data)
        outrec.contentData = data
        outrec.contentLength = len(data)
        outrec.write(sock)

        # Await response
        inrec = Record()
        inrec.read(sock)
        result = {}
        if inrec.type == FCGI_GET_VALUES_RESULT:
            pos = 0
            while pos < inrec.contentLength:
                pos, (name, value) = decode_pair(inrec.contentData, pos)
                result[name] = value
        return result

    def _fcgiParams(self, sock, requestId, params):
        rec = Record(FCGI_PARAMS, requestId)
        data = []
        for name, value in params.items():
            data.append(encode_pair(name, value))
        data = ''.join(data)
        rec.contentData = data
        rec.contentLength = len(data)
        rec.write(sock)

    _environPrefixes = ['SERVER_', 'HTTP_', 'REQUEST_', 'REMOTE_', 'PATH_',
                        'CONTENT_', 'DOCUMENT_', 'SCRIPT_']
    _environCopies = ['SCRIPT_NAME', 'QUERY_STRING', 'AUTH_TYPE']
    _environRenames = {}

    def _defaultFilterEnviron(self, environ):
        result = {}
        for n in environ.keys():
            for p in self._environPrefixes:
                if n.startswith(p):
                    result[n] = environ[n]
            if n in self._environCopies:
                result[n] = environ[n]
            if n in self._environRenames:
                result[self._environRenames[n]] = environ[n]

        return result

    def _lightFilterEnviron(self, environ):
        result = {}
        for n in environ.keys():
            if n.upper() == n:
                result[n] = environ[n]
        return result


def phpfpmparam(port, param, host, url):
    fcgi = FCGIApp(host=host, port=port)
    script = url
    query = 'json'
    env = {
        'SCRIPT_NAME': script,
        'SCRIPT_FILENAME': script,
        'QUERY_STRING': query,
        'REQUEST_METHOD': 'GET'}
    code, headers, out, err = fcgi(env)
    return(json.loads(out)[param.replace("_", " ")])


def find_port(berceau):
    for configdir in phpfpmdir:
        for dirpath, dirnames, filenames in walk(configdir):
            for filename in filenames:
                find = False
                for line in open(path.join(dirpath, filename), 'r'):
                    if re.search("listen =", line):
                        port = line.split(':')[1]
                    if re.search("\[%s\]" % (berceau), line):
                            find = True
                if find:
                        try:
                            return int(port)
                        except ValueError:
                            print("error during config parse")
                            return None


def discover():
    retour = {"data": []}
        # je cherche les berceaux
    for dirpath, dirnames, filenames in walk(webmin_root):
        for filename in filenames:
            for line in open(path.join(dirpath, filename), 'r'):
                m = re.search('^user\=(.+)', line)
                if m is not None:
                    retour["data"].append({"{#PHPBERCEAU}": m.group(1)})
    return retour


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='php-fpm status requester')
    parser.add_argument('--discovery',
                        action="store_true",
                        help='parse config')
    parser.add_argument('--port',
                        action="store_true",
                        help='specify port instead of config name')
    parser.add_argument('--host',
                        default="127.0.0.1",
                        help='specify php-fpm host')
    parser.add_argument('--url',
                        help='defaut is /php-fpm-[port-number]')
    parser.add_argument('config',
                        nargs='?',
                        help='config/port keyword')
    parser.add_argument('command',
                        nargs='?',
                        help='config/port keyword')
    args = parser.parse_args()

    port = None
    url = None
    discovery = None
    configload = False
    try:
        with open(CONFIGFILE) as json_data:
            d = json.load(json_data)
            if "url" in d:
                url = d["url"]
            if "host" in d:
                host = d["host"]
            if "discovery" in d:
                discovery = d["discovery"]
    except ValueError:
        print("Erreur dans le fichier de config %s" % (CONFIGFILE))
        exit(-1)
    except IOError:
        print("pas de fichier de conf")

    if args.discovery:
        if (discovery is None):
            discovery = discover()
        print json.dumps(discovery)

    else:
        if (args.command is None) or (args.config is None):
            parser.print_help()
        else:
            if (discovery is not None):
                port = int(args.config)
            elif (discovery is None):
                port = find_port(args.config)
                if (port is None):
                    print("Impossible de récupérer le port, Bye!")
                    exit(-1)
            if ((args.url is None) & (url is None)):
                url = "/php-fpm-%d" % (port)
            elif (url is None):
                url = args.url
            if (host is None):
                host = args.host
            print (phpfpmparam(port=port,
                               param=args.command,
                               host=host, url=url))
    exit(0)
