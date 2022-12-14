from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import flask_sqlalchemy

try:
    import ConfigParser as configparser
except ImportError:
    import configparser

try:
    from ipaddr import IPAddress as ip_address
except ImportError:
    from ipaddress import ip_address

try:
    import GeoIP as geoip1

    geoip1_available = True
except ImportError:
    geoip1_available = False

try:
    from geoip2 import database
    from geoip2.errors import AddressNotFoundError

    geoip2_available = True
except ImportError:
    geoip2_available = False

import argparse
import os
import re
import socket
import string
import sys
import json
import requests
from collections import namedtuple
from json import JSONEncoder
from datetime import datetime, timedelta
from humanize import naturalsize
from collections import OrderedDict, deque
from pprint import pformat
from semantic_version import Version as semver
# from flask import Flask, request, jsonify
from flask import Flask,session, request,send_from_directory, send_file, render_template, url_for, jsonify, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
from sqlalchemy.ext.declarative import DeclarativeMeta
from dbconf import Conf
import jwt
from encrypt import AESCipher
#from jwcrypto import jwe, jwt
# from radiusClass.nas import Nas

# Init App
appConf = Conf()
appConf.confSys()
app = appConf.FlaskConf()
db = appConf.DBConf()
cors = appConf.Cors()
encrypt = AESCipher(b'zM6WNtrCoFMa3cNkGy2p9Yw1RGB-JJD4nlwZy4121MI=')
# app.config['SECRET_KEY'] = 'thisissecret'
# our database uri
# username = "postgres"
# password = "castillo30"
# dbname = "radius"
# dbname2 = "vpnManager"
# domain = "20.124.105.127"
# port = "5432"
# app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql://{username}:{password}@{domain}:{port}/{dbname}"
# app.config["SQLALCHEMY_BINDS"] = {
#     dbname2:        f"postgresql://{username}:{password}@{domain}:{port}/{dbname2}"
# }


from radiusClass.nas import Nas
from radiusClass.radacct import Radacct
from radiusClass.radcheck import Radcheck

from classP.administrador import Administrador
from classP.client import Client
from classP.packSubcription import PackSubcription
from classP.invoice import Invoice
from classP.detailInvoice import DetailInvoice
from classP.comp import Comp
from classP.clientPackSubcription import ClientPackSubcription



from classP.vpnServer import VpnServer


# Create A Model For Table
# class BlogPosts(db.Model):
#     __tablename__ = 'blogposts'
#     id = db.Column(db.Integer, primary_key=True)
#     blog_title = db.Column(db.String(1000))
#     blog_description = db.Column(db.String(6000))
# pubKey = {'k':\
#            '-----BEGIN PUBLIC KEY-----\n'+
# 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjApRwRb3gL5u9FJsYZJP\n'+
# 'TxkASU0nYAsOXdAsQWrWLzC401xUatJLrKm6fViXEnCgtJP957z8EmaiG4uY2iV3\n'+
# 'ufvb8JS6t2GTF0/xHyGKpbQrW/RZaXGKV3N9wL53O/O+V7hxlAxXxygLZ/xXb/+U\n'+
# '5lmEyUWtyBWpazpuR0jAVy/dwvtkwLQr5EZdmF7DgzVElYeWbK5LGrZkQ97WUXh1\n'+
# 'KxyOZuN5sP0jdo1y+3fWuNgj4rZ/YwPhvVA1AlkDzl++zJ0hZQSjz9JWQMm/ek7l\n'+
# 'RNhDuLB5j20IbZdj22nOkYnIFrixFbaXPZ/2SgTexmmf+Zl9y6lw5hwaJxJl6/84\n'+
# 'IwIDAQAB\n'+
# '-----END PUBLIC KEY-----'
#     }
# # decrypt on the other end using the private key
# privKey = {'k': 
#     '-----BEGIN RSA PRIVATE KEY-----\n'+
#     'MIIEpAIBAAKCAQEAjApRwRb3gL5u9FJsYZJPTxkASU0nYAsOXdAsQWrWLzC401xU\n'+
# 'atJLrKm6fViXEnCgtJP957z8EmaiG4uY2iV3ufvb8JS6t2GTF0/xHyGKpbQrW/RZ\n'+
# 'aXGKV3N9wL53O/O+V7hxlAxXxygLZ/xXb/+U5lmEyUWtyBWpazpuR0jAVy/dwvtk\n'+
# 'wLQr5EZdmF7DgzVElYeWbK5LGrZkQ97WUXh1KxyOZuN5sP0jdo1y+3fWuNgj4rZ/\n'+
# 'YwPhvVA1AlkDzl++zJ0hZQSjz9JWQMm/ek7lRNhDuLB5j20IbZdj22nOkYnIFrix\n'+
# 'FbaXPZ/2SgTexmmf+Zl9y6lw5hwaJxJl6/84IwIDAQABAoIBABb4glyH5eVKV2zg\n'+
# 'MEL4+uVglnlvnGvWpG6i/P9mBOgMt+SDmp1DDYKu/JYe9/jgXJwCQn3GtBpYl3Kp\n'+
# 'PVNbHf5136fg3ZfC+5uxUz3mBJYVrZ8Rv7DaHPUnTpNVKr28x5Yf/RFpzOQwH17Z\n'+
# 'N4Z5h/UY7f0N3umZFAcwuHIc7t/eDNxRHhYhCMWkzYESEZ40IqRrVfdnwfNLE/Kf\n'+
# 'pyp48Nv2cTOns24aX8YsXsJR61Ku9ylVNgX+6PsCQZsuGC+uYmPKBFSpmzplXkjz\n'+
# 'rl60M4ruf9+ImEQiTf7j2drRKm8cR7pF4KbdWt4W2FyGQhZQ8uoK6P6q5w+D/LOr\n'+
# 'utZC4+ECgYEA5bpMJjUPT+6jO3hP3p1Bwxc0qyMCW1J5vb7a3myuYRqd5K+IAWSy\n'+
# '0IWexJNFthNC8BQcrdW6JfbiptBpixOnsZpt6tguTY+q+dgRe7QGxsoBLZ1r/gr2\n'+
# 'JtGwBzhq/u7v+PRmcrsuzGkED1oMS1+B0H1EQsExfYmuIEN7T75zSOkCgYEAnA5B\n'+
# '7b0mex2noXAJHWDie4bZjdL9TOrWgbXX9xS/hVmGZgjf8eWPxLYPkei6NX5Un2Qw\n'+
# '9Q2336QPDAqaFwCTVChQ1eWd/ualjwenqKQqoarxgCxOocr82wIFikvDrNAFVT23\n'+
# 'en1xCFTUhVzhmsVHg2Z51O/Mo7ecsaVIWHnmkSsCgYEAux/H/WtFAMAKuFtk+5ku\n'+
# 'wwH5BdmrhsWkorl+wKTYWgJ7UJbmevQSb6YX0FmB9DC2WqaXQcYRLfFvZ5/mCMJG\n'+
# '23VGSYA0HzuCcqbcft4CkxRiZ0yOdc1p+e7dqtP625O3Zxt1A8mS8jAsfXDFCPRP\n'+
# '4orW+mUxsedfLaqqHCeu8lkCgYBkxPQfnyeNEo4fOeg410oIOACdiyPTmkUfhxvI\n'+
# 'ydYONswJcSui2PioLmQJdP1g842TSzAt3Ujhmd+5h9MOjWmVS18/b8FBSxCXNns1\n'+
# '86QvtuGxQWsZIKl8hmarcdcN7Vm0PGERMJVfqt98qohn14IhQHflX1+GTFdbgv4f\n'+
# 'W7/d9wKBgQC0Zes/d7wLFnDJKnhIz0dLExT4QdA5iN7f3h4uPGdiaUBwQ/4ZVqrx\n'+
# 'EnLP1WkU0Zmb6naeYmvw5VXvs9N3FK0rAXsQe0uvM60d2u8QHMYm5LekCClguDWG\n'+
# 'i3EhfU/HrGeB/eEZPPdv0zL7xcvZG+5pW1apo/qa3trOMhwSszhEMQ==\n'+
# '-----END RSA PRIVATE KEY-----'
# }

# def jwtEncrypt(claims):
#     eprot = {'alg': "RSA-OAEP", 'enc': "A128CBC-HS256"}
#     E = jwe.JWE(json.dumps(claims), json.dumps(eprot))
#     E.add_recipient(pubKey)
#     encrypted_token = E.serialize(compact=True)
#     return encrypted_token
# def jwrDesencrypt(token):
#     E = jwe.JWE()
#     E.deserialize(token, key=privKey)
#     decrypted_payload = E.payload
#     return decrypted_payload


class AlchemyEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj.__class__, DeclarativeMeta):
            # an SQLAlchemy class
            fields = {}
            for field in [x for x in dir(obj) if not x.startswith('_') and x != 'metadata']:

                data = obj.__getattribute__(field)
                try:
                    print(field)
                    print(type(data))
                    print(data)
                    if isinstance(data, datetime):
                        fields[field] = str(data)
                    elif isinstance(data, flask_sqlalchemy.BaseQuery):
                        fields[field] = None
                        # fields[field] = str(data)
                    else:
                        json.dumps(data)  # this will fail on non-encodable values, like other classes
                        fields[field] = data
                except TypeError:
                    fields[field] = None
            # a json-encodable dict
            return fields
        elif isinstance(obj, datetime):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


# 	def __init__(self,
# id,nasname,shortname,type,ports,secret,server,community,description):


if sys.version_info[0] == 2:
    reload(sys)  # noqa
    sys.setdefaultencoding('utf-8')


# app = Flask(__name__)

def output(s):
    global wsgi, wsgi_output
    if not wsgi:
        print(s)
    else:
        wsgi_output += s


def info(*objs):
    print("INFO:", *objs, file=sys.stderr)


def warning(*objs):
    print("WARNING:", *objs, file=sys.stderr)


def debug(*objs):
    print("DEBUG:\n", *objs, file=sys.stderr)


def get_date(date_string, uts=False):
    if not uts:
        return datetime.strptime(date_string, "%a %b %d %H:%M:%S %Y")
    else:
        return datetime.fromtimestamp(float(date_string))


def get_str(s):
    if sys.version_info[0] == 2 and s is not None:
        return s.decode('ISO-8859-1')
    else:
        return s


def is_truthy(s):
    return s in ['True', 'true', 'Yes', 'yes', True]


class ConfigLoader(object):

    def __init__(self, config_file, serverID):
        self.settings = {}
        self.vpns = OrderedDict()
        config = configparser.RawConfigParser()
        contents = config.read(config_file)

        if not contents and config_file == './openvpn-monitor.conf':
            warning('Config file does not exist or is unreadable: {0!s}'.format(config_file))
            if sys.prefix == '/usr':
                conf_path = '/etc/'
            else:
                conf_path = sys.prefix + '/etc/'
            config_file = conf_path + 'openvpn-monitor.conf'
            contents = config.read(config_file)

        if contents:
            info('Using config file: {0!s}'.format(config_file))
        else:
            warning('Config file does not exist or is unreadable: {0!s}'.format(config_file))
            self.load_default_settings()

        for section in config.sections():
            if section.lower() == 'openvpn-monitor':
                self.parse_global_section(config)
            # else:
            #     self.parse_vpn_section(config, section)
        # self.parse_vpn_section(config, section)
        print('dbTurno')
        print(serverID)
        if serverID is not None:
            self.parse_vpn_section_db_specific(serverID)
        else:
            self.parse_vpn_section_db()

    def load_default_settings(self):
        print('Entro local')

        info('Using default settings => localhost:5555')
        self.settings = {'site': 'Default Site',
                         'maps': 'True',
                         'geoip_data': '/usr/share/GeoIP/GeoIPCity.dat',
                         'datetime_format': '%d/%m/%Y %H:%M:%S'}
        self.vpns['Default VPN'] = {'name': 'default',
                                    'host': 'localhost',
                                    'port': '5555',
                                    'password': '',
                                    'show_disconnect': False}

    def parse_global_section(self, config):
        print('Entro global')
        global_vars = ['site', 'logo', 'latitude', 'longitude', 'maps', 'maps_height', 'geoip_data', 'datetime_format']
        for var in global_vars:
            try:
                self.settings[var] = config.get('openvpn-monitor', var)
            except configparser.NoSectionError:
                # backwards compat
                try:
                    self.settings[var] = config.get('OpenVPN-Monitor', var)
                except configparser.NoOptionError:
                    pass
            except configparser.NoOptionError:
                pass
        if args.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(self.settings))

    def parse_vpn_section(self, config, section):
        print('entro vpn section')
        self.vpns[section] = {}
        vpn = self.vpns[section]
        options = config.options(section)
        for option in options:
            print(option)
            try:
                vpn[option] = config.get(section, option)
                if vpn[option] == -1:
                    warning('CONFIG: skipping {0!s}'.format(option))
            except configparser.Error as e:
                warning('CONFIG: {0!s} on option {1!s}: '.format(e, option))
                vpn[option] = None
        vpn['show_disconnect'] = is_truthy(vpn.get('show_disconnect', False))
        if args.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(vpn))

    def parse_vpn_section_db(self):
        vpnServer = VpnServer.query.all()
        for value in vpnServer:
            self.vpns[value.id] = {}
            vpn = self.vpns[value.id]
            # options = config.options(section)
            # vpn['host'] = value.id
            # vpn['port'] = value.port
            # vpn['name'] = value.name
            # vpn['password'] = value.password
            # vpn['show_disconnect'] = value.show_disconnect
            print(type(value))
            for key in value.__dict__:

                try:

                    vpn[key] = value.__dict__[key]
                    if vpn[key] == -1:
                        warning('CONFIG: skipping {0!s}'.format(key))
                except Exception as e:
                    warning('CONFIG: {0!s} on option {1!s}: '.format(e, key))
                    vpn[key] = None
            vpn['show_disconnect'] = is_truthy(vpn.get('show_disconnect', False))
            if args.debug:
                debug("=== begin section\n{0!s}\n=== end section".format(vpn))
            # print(value.id)

        # for option in options:
        #     try:
        #         vpn[option] = config.get(section, option)
        #         if vpn[option] == -1:
        #             warning('CONFIG: skipping {0!s}'.format(option))
        #     except configparser.Error as e:
        #         warning('CONFIG: {0!s} on option {1!s}: '.format(e, option))
        #         vpn[option] = None
        # vpn['show_disconnect'] = is_truthy(vpn.get('show_disconnect', False))
        # if args.debug:
        #     debug("=== begin section\n{0!s}\n=== end section".format(vpn))

    def parse_vpn_section_db_specific(self, id):

        value = VpnServer.query.filter_by(id=id).first()
        self.vpns[value.id] = {}
        vpn = self.vpns[value.id]
        # options = config.options(section)
        # vpn['host'] = value.id
        # vpn['port'] = value.port
        # vpn['name'] = value.name
        # vpn['password'] = value.password
        # vpn['show_disconnect'] = value.show_disconnect
        print(type(value))
        for key in value.__dict__:

            try:

                vpn[key] = value.__dict__[key]
                if vpn[key] == -1:
                    warning('CONFIG: skipping {0!s}'.format(key))
            except Exception as e:
                warning('CONFIG: {0!s} on option {1!s}: '.format(e, key))
                vpn[key] = None
        vpn['show_disconnect'] = is_truthy(vpn.get('show_disconnect', False))
        if args.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(vpn))


class OpenvpnMgmtInterface(object):

    def __init__(self, cfg, **kwargs):
        self.vpns = cfg.vpns

        if kwargs.get('vpn_id'):
            vpn = self.vpns[kwargs['vpn_id']]
            disconnection_allowed = vpn['show_disconnect']
            if disconnection_allowed:
                self._socket_connect(vpn)
                if vpn['socket_connected']:
                    release = self.send_command('version\n')
                    version = semver(self.parse_version(release).split(' ')[1])
                    command = False
                    client_id = int(kwargs.get('client_id'))
                    if version.major == 2 and \
                            version.minor >= 4 and \
                            client_id:
                        command = 'client-kill {0!s}\n'.format(client_id)
                    else:
                        ip = ip_address(kwargs['ip'])
                        port = int(kwargs['port'])
                        if ip and port:
                            command = 'kill {0!s}:{1!s}\n'.format(ip, port)
                    if command:
                        self.send_command(command)
                    self._socket_disconnect()

        geoip_data = cfg.settings['geoip_data']
        self.geoip_version = None
        self.gi = None
        try:
            if geoip_data.endswith('.mmdb') and geoip2_available:
                self.gi = database.Reader(geoip_data)
                self.geoip_version = 2
            elif geoip_data.endswith('.dat') and geoip1_available:
                self.gi = geoip1.open(geoip_data, geoip1.GEOIP_STANDARD)
                self.geoip_version = 1
            else:
                warning('No compatible geoip1 or geoip2 data/libraries found.')
        except IOError:
            warning('No compatible geoip1 or geoip2 data/libraries found.')

        for _, vpn in list(self.vpns.items()):
            self._socket_connect(vpn)
            if vpn['socket_connected']:
                self.collect_data(vpn)
                self._socket_disconnect()

    def collect_data(self, vpn):
        ver = self.send_command('version\n')
        vpn['release'] = self.parse_version(ver)
        vpn['version'] = semver(vpn['release'].split(' ')[1])
        state = self.send_command('state\n')
        vpn['state'] = self.parse_state(state)
        stats = self.send_command('load-stats\n')
        vpn['stats'] = self.parse_stats(stats)
        status = self.send_command('status 3\n')
        vpn['sessions'] = self.parse_status(status, vpn['version'])

    def _socket_send(self, command):
        if sys.version_info[0] == 2:
            self.s.send(command)
        else:
            self.s.send(bytes(command, 'utf-8'))

    def _socket_recv(self, length):
        if sys.version_info[0] == 2:
            return self.s.recv(length)
        else:
            return self.s.recv(length).decode('utf-8')

    def _socket_connect(self, vpn):
        timeout = 3
        self.s = False
        try:
            if vpn.get('socket'):
                self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.s.connect(vpn['socket'])
            else:
                host = vpn['host']
                port = int(vpn['port'])
                self.s = socket.create_connection((host, port), timeout)
            if self.s:
                password = vpn.get('password')
                if password:
                    self.wait_for_data(password=password)
                vpn['socket_connected'] = True
        except socket.timeout as e:
            vpn['error'] = '{0!s}'.format(e)
            warning('socket timeout: {0!s}'.format(e))
            vpn['socket_connected'] = False
            if self.s:
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
        except socket.error as e:
            vpn['error'] = '{0!s}'.format(e.strerror)
            warning('socket error: {0!s}'.format(e))
            vpn['socket_connected'] = False
        except Exception as e:
            vpn['error'] = '{0!s}'.format(e)
            warning('unexpected error: {0!s}'.format(e))
            vpn['socket_connected'] = False

    def _socket_disconnect(self):
        self._socket_send('quit\n')
        self.s.shutdown(socket.SHUT_RDWR)
        self.s.close()

    def send_command(self, command):
        info('Sending command: {0!s}'.format(command))
        self._socket_send(command)
        if command.startswith('kill') or command.startswith('client-kill'):
            return
        return self.wait_for_data(command=command)

    def wait_for_data(self, password=None, command=None):
        data = ''
        while 1:
            socket_data = self._socket_recv(1024)
            socket_data = re.sub('>INFO(.)*\r\n', '', socket_data)
            data += socket_data
            if data.endswith('ENTER PASSWORD:'):
                if password:
                    self._socket_send('{0!s}\n'.format(password))
                else:
                    warning('password requested but no password supplied by configuration')
            if data.endswith('SUCCESS: password is correct\r\n'):
                break
            if command == 'load-stats\n' and data != '':
                break
            elif data.endswith("\nEND\r\n"):
                break
        if args.debug:
            debug("=== begin raw data\n{0!s}\n=== end raw data".format(data))
        return data

    @staticmethod
    def parse_state(data):
        state = {}
        for line in data.splitlines():
            parts = line.split(',')
            if args.debug:
                debug("=== begin split line\n{0!s}\n=== end split line".format(parts))
            if parts[0].startswith('>INFO') or \
                    parts[0].startswith('END') or \
                    parts[0].startswith('>CLIENT'):
                continue
            else:
                state['up_since'] = get_date(date_string=parts[0], uts=True)
                state['connected'] = parts[1]
                state['success'] = parts[2]
                if parts[3]:
                    state['local_ip'] = ip_address(parts[3])
                    # state['local_ip'] = parts[3]
                else:
                    state['local_ip'] = ''
                if parts[4]:
                    state['remote_ip'] = ip_address(parts[4])
                    state['mode'] = 'Client'
                else:
                    state['remote_ip'] = ''
                    state['mode'] = 'Server'
        return state

    @staticmethod
    def parse_stats(data):
        stats = {}
        line = re.sub('SUCCESS: ', '', data)
        parts = line.split(',')
        if args.debug:
            debug("=== begin split line\n{0!s}\n=== end split line".format(parts))
        stats['nclients'] = int(re.sub('nclients=', '', parts[0]))
        stats['bytesin'] = int(re.sub('bytesin=', '', parts[1]))
        stats['bytesout'] = int(re.sub('bytesout=', '', parts[2]).replace('\r\n', ''))
        return stats

    def parse_status(self, data, version):
        gi = self.gi
        geoip_version = self.geoip_version
        client_section = False
        routes_section = False
        sessions = {}
        client_session = {}

        for line in data.splitlines():
            parts = deque(line.split('\t'))
            if args.debug:
                debug("=== begin split line\n{0!s}\n=== end split line".format(parts))

            if parts[0].startswith('END'):
                break
            if parts[0].startswith('TITLE') or \
                    parts[0].startswith('GLOBAL') or \
                    parts[0].startswith('TIME'):
                continue
            if parts[0] == 'HEADER':
                if parts[1] == 'CLIENT_LIST':
                    client_section = True
                    routes_section = False
                if parts[1] == 'ROUTING_TABLE':
                    client_section = False
                    routes_section = True
                continue

            if parts[0].startswith('TUN') or \
                    parts[0].startswith('TCP') or \
                    parts[0].startswith('Auth'):
                parts = parts[0].split(',')
            if parts[0] == 'TUN/TAP read bytes':
                client_session['tuntap_read'] = int(parts[1])
                continue
            if parts[0] == 'TUN/TAP write bytes':
                client_session['tuntap_write'] = int(parts[1])
                continue
            if parts[0] == 'TCP/UDP read bytes':
                client_session['tcpudp_read'] = int(parts[1])
                continue
            if parts[0] == 'TCP/UDP write bytes':
                client_session['tcpudp_write'] = int(parts[1])
                continue
            if parts[0] == 'Auth read bytes':
                client_session['auth_read'] = int(parts[1])
                sessions['Client'] = client_session
                continue

            if client_section:
                session = {}
                parts.popleft()
                common_name = parts.popleft()
                remote_str = parts.popleft()
                if remote_str.count(':') == 1:
                    remote, port = remote_str.split(':')
                elif '(' in remote_str:
                    remote, port = remote_str.split('(')
                    port = port[:-1]
                else:
                    remote = remote_str
                    port = None
                remote_ip = ip_address(remote)
                session['remote_ip'] = remote_ip
                if port:
                    session['port'] = int(port)
                else:
                    session['port'] = ''
                if session['remote_ip'].is_private:
                    session['location'] = 'RFC1918'
                elif session['remote_ip'].is_loopback:
                    session['location'] = 'loopback'
                else:
                    try:
                        if geoip_version == 1:
                            gir = gi.record_by_addr(str(session['remote_ip']))
                            if gir is not None:
                                session['location'] = gir['country_code']
                                session['region'] = get_str(gir['region'])
                                session['city'] = get_str(gir['city'])
                                session['country'] = gir['country_name']
                                session['longitude'] = gir['longitude']
                                session['latitude'] = gir['latitude']
                        elif geoip_version == 2:
                            gir = gi.city(str(session['remote_ip']))
                            session['location'] = gir.country.iso_code
                            session['region'] = gir.subdivisions.most_specific.iso_code
                            session['city'] = gir.city.name
                            session['country'] = gir.country.name
                            session['longitude'] = gir.location.longitude
                            session['latitude'] = gir.location.latitude
                    except AddressNotFoundError:
                        pass
                    except SystemError:
                        pass
                local_ipv4 = parts.popleft()
                if local_ipv4:
                    session['local_ip'] = ip_address(local_ipv4)
                else:
                    session['local_ip'] = ''
                if version.major >= 2 and version.minor >= 4:
                    local_ipv6 = parts.popleft()
                    if local_ipv6:
                        session['local_ip'] = ip_address(local_ipv6)
                session['bytes_recv'] = int(parts.popleft())
                session['bytes_sent'] = int(parts.popleft())
                parts.popleft()
                session['connected_since'] = get_date(parts.popleft(), uts=True)
                username = parts.popleft()
                if username != 'UNDEF':
                    session['username'] = username
                else:
                    session['username'] = common_name
                if version.major == 2 and version.minor >= 4:
                    session['client_id'] = parts.popleft()
                    session['peer_id'] = parts.popleft()
                sessions[str(session['local_ip'])] = session

            if routes_section:
                local_ip = parts[1]
                remote_ip = parts[3]
                last_seen = get_date(parts[5], uts=True)
                if sessions.get(local_ip):
                    sessions[local_ip]['last_seen'] = last_seen
                elif self.is_mac_address(local_ip):
                    matching_local_ips = [sessions[s]['local_ip']
                                          for s in sessions if remote_ip ==
                                          self.get_remote_address(sessions[s]['remote_ip'], sessions[s]['port'])]
                    if len(matching_local_ips) == 1:
                        local_ip = '{0!s}'.format(matching_local_ips[0])
                        if sessions[local_ip].get('last_seen'):
                            prev_last_seen = sessions[local_ip]['last_seen']
                            if prev_last_seen < last_seen:
                                sessions[local_ip]['last_seen'] = last_seen
                        else:
                            sessions[local_ip]['last_seen'] = last_seen

        if args.debug:
            if sessions:
                pretty_sessions = pformat(sessions)
                debug("=== begin sessions\n{0!s}\n=== end sessions".format(pretty_sessions))
            else:
                debug("no sessions")

        return sessions

    @staticmethod
    def parse_version(data):
        for line in data.splitlines():
            if line.startswith('OpenVPN'):
                return line.replace('OpenVPN Version: ', '')

    @staticmethod
    def is_mac_address(s):
        return len(s) == 17 and \
               len(s.split(':')) == 6 and \
               all(c in string.hexdigits for c in s.replace(':', ''))

    @staticmethod
    def get_remote_address(ip, port):
        if port:
            return '{0!s}:{1!s}'.format(ip, port)
        else:
            return '{0!s}'.format(ip)


def customVaDecoder(va):
    return namedtuple('X', va.keys())(*va.values())


def main(**kwargs):
    args = get_args()
    print(args.config)
    print('ya --')
    cfg = ConfigLoader(args.config,None)
    monitor = OpenvpnMgmtInterface(cfg, **kwargs)
    pretty_vpns = pformat((dict(monitor.vpns)))
    debug("=== begin vpns\n{0!s}\n=== end vpns".format(pretty_vpns))

    return pretty_vpns
    # if args.debug:
    #     pretty_vpns = pformat((dict(monitor.vpns)))
    #     debug("=== begin vpns\n{0!s}\n=== end vpns".format(pretty_vpns))
def getServerInformation(**kwargs):
    args = get_args()
    print(args.config)
    print('ya --')
    cfg = ConfigLoader(args.config, kwargs.get('id'))
    monitor = OpenvpnMgmtInterface(cfg, **kwargs)
    pretty_vpns = pformat((dict(monitor.vpns)))
    debug("=== begin vpns\n{0!s}\n=== end vpns".format(pretty_vpns))

    return dict(monitor.vpns)


def get_args():
    parser = argparse.ArgumentParser(
        description='Display a html page with openvpn status and connections')
    parser.add_argument('-d', '--debug', action='store_true',
                        required=False, default=False,
                        help='Run in debug mode')
    parser.add_argument('-c', '--config', type=str,
                        required=False, default='./openvpn-monitor.conf',
                        help='Path to config file openvpn-monitor.conf')
    return parser.parse_args()


def _json_object_hook(d): return namedtuple('X', d.keys())(*d.values())


@app.before_request
def before_request_func():
    headers = request.headers
    auth = headers.get("X-Api-Key")
    if request.path =='/login' or request.path =='/status' or request.path =='/':
        print('Its ok')
    else:
        if auth is not None:
            print('bien')
            try:
                decode_token = encrypt.decrypt(auth)
                print("Token is still valid and active")
            except jwt.ExpiredSignatureError:
                print("Token expired. Get new one")
            except jwt.InvalidTokenError:
                print("Invalid Token")
        elif 'user' in session:
            print('Its ok')
        else:
            return "Error"
        # try:
        #     decode_token = jwt.decode(encoded_token, 'MySECRET goes here', algorithms=['HS256'])
        #     print("Token is still valid and active")
        # except jwt.ExpiredSignatureError:
        #     print("Token expired. Get new one")
        # except jwt.InvalidTokenError:
        #     print("Invalid Token")


@app.route('/status', methods=['GET', 'POST'])
@cross_origin()
def index():
    content_type = request.headers.get('Content-Type')
    print(content_type)
    if (content_type == 'application/json'):
        print('entro')
        if request.method == 'POST':
            json_data = request.get_json()
            jsonstr1 = json.dumps({"status": False, "token": None}, cls=AlchemyEncoder)

            try:
                decode_token = encrypt.decrypt(json_data["token"])
                jsonstr1 = json.dumps({"status": True, "token": encrypt.encrypt(decode_token)}, cls=AlchemyEncoder)
                print("Token is still valid and active")
                return jsonstr1

            except jwt.ExpiredSignatureError as e:
                print("Token expired. Get new one")
                return jsonstr1
            except jwt.InvalidTokenError:
                print("Invalid Token")
                return jsonstr1



    else:
        jsonstr1 = json.dumps({"status": False, "token": None}, cls=AlchemyEncoder)
        return jsonstr1


@app.route('/login', methods=['GET', 'POST'])
@cross_origin()
def login():
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        if request.method == 'POST':
            json_data = request.get_json()
            adm = None
            passwordS = None
            try:
                adm = Administrador.query.filter_by(usuario=json_data['usuario']).first()
                passwordS = json_data['password']
            except:
                adm = None
                passwordS = None
            if adm is not None:
                print(adm.password)
                password = encrypt.decrypt(adm.password)
                if password['password'] == passwordS:
                    session['user'] = json_data['usuario']
                    vari = None
                    dt = datetime.now() + timedelta(days=2)
                    ewc = {
                        "user": json_data['usuario'],
                        "fullname": adm.nombre + ' '+adm.apellido,
                        "exp": dt
                    }
                    vari = {
                        "user": json_data['usuario'],
                        "email": adm.email,
                        "fullname": adm.nombre + ' ' + adm.apellido,
                        "token": encrypt.encrypt(ewc),
                        "status": 1
                    }
                    jsonstr1 = json.dumps(vari, cls=AlchemyEncoder)
                    return jsonstr1
                    # return 'Logged in as: ' + session['user'] + '<a href="/logout"> Log out</a>'
                else:
                    return 'UserAndPasswordIncorrect'
            else:
                return 'UserAndPasswordIncorrect'
        
    else:
        return 404

@app.route('/logout', methods=['GET', 'POST'])
@cross_origin()
def logout():
	session.pop('user', None)
	return "ok"


@app.route('/', methods=['GET', 'POST'])
@cross_origin()
def welcome():
    return "Hello World!"


@app.route("/get-files/<string:filename>")
@cross_origin()
def return_pdf(filename):
    try:
        print('entro'+os.getcwd()+'\\images\\flags\\')
        return send_from_directory('images/flags/', filename, as_attachment=True)
    except FileNotFoundError:
        return 404

@app.route('/openvpn-monitor/', methods=['GET'])
@cross_origin()
def monitor():
    # args = get_args()
    # wsgi = False
    aux = getServerInformation()
    print(type(aux))

    # jsonStr2 = json.loads(aux)
    # debug("{0!s}".format(aux)) esefun
    # debug("{0!s}".format(jsonStr))
    # debug("{0!s}".format(jsonStr2))
    # return jsonify(jsonStr)
    # print(type(aux))
    # return aux

    listRet = []
    for value in aux:
        aux[value]['_sa_instance_state'] = None
        try:
            aux[value]['state']['local_ip'] = str(aux[value]['state']['local_ip'])
            if aux[value]['state']['remote_ip']  is not None:

                aux[value]['state']['remote_ip'] = str(aux[value]['state']['remote_ip'])
        except:
            print('no found')
        try:
            aux[value]['version'] = str(aux[value]['version'])
        except:
            print('no found')
        try:
            aux[value]['state']['up_since'] = int(round(aux[value]['state']['up_since'].timestamp()))
            print(aux[value]['state']['up_since'])
        except:
            print('no found')
        try:
            for val in aux[value]['sessions']:
                aux[value]['sessions'][val]['connected_since'] = int(round(aux[value]['sessions'][val]['connected_since'].timestamp()))
                aux[value]['sessions'][val]['last_seen'] = int(round(aux[value]['sessions'][val]['last_seen'].timestamp()))
                aux[value]['sessions'][val]['local_ip'] = str(aux[value]['sessions'][val]['local_ip'])
                aux[value]['sessions'][val]['remote_ip'] = str(aux[value]['sessions'][val]['remote_ip'])

        except:
            print('no found')

        # print(aux[value]['state']['local_ip'])

        listRet.append(aux[value])
    print(listRet)
    jsonstr1 = json.dumps(listRet, default=lambda o: o.__dict__,
            sort_keys=True )
    return jsonstr1


@app.route('/radacct', methods=['GET'])
@cross_origin()
def radacct():
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        print(type('string'))
        # <class 'str'>
        posts = Radacct.query.all()
        # print(type(posts))
        # jsonStr2 = json.loads(posts)
        # debug("{0!s}".format(posts))
        # debug("{0!s}".format(jsonStr2))
        # jsonStr = json.dumps(posts)
        listRet = []
        for value in posts:
            listRet.append(value)
        jsonstr1 = json.dumps(listRet, cls=AlchemyEncoder)
        return jsonstr1


@app.route('/nas', methods=['GET'])
@cross_origin()
def nas():
    print(type('string'))
    # <class 'str'>

    posts = Nas.query.all()
    # print(type(posts))
    # jsonStr2 = json.loads(posts)
    # debug("{0!s}".format(posts))
    # debug("{0!s}".format(jsonStr2))
    # jsonStr = json.dumps(posts)
    listRet = []
    for value in posts:
        print(value.id)
        listRet.append(value)
    jsonstr1 = json.dumps(listRet, cls=AlchemyEncoder)
    return jsonstr1
    # return render_template("index.html",posts=posts)


@app.route('/nasobject', methods=['POST', 'GET'])
@cross_origin()
def nasobject():
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        if request.method == 'POST':
            json_data = request.get_json()
            nasname = json_data['nasname']
            shortname = json_data['shortname']
            type1 = json_data['type']
            ports = json_data['ports']
            secret = json_data['secret']
            server = json_data['server']
            community = json_data['community']
            description = json_data['description']

            nas = Nas(nasname=nasname, shortname=shortname, type=type1, ports=ports, secret=secret, server=server,
                      community=community, description=description)
            db.session.add(nas)
            # db.session.commit()
            db.session.flush()
            db.session.refresh(nas)
            db.session.commit()

            jsonstr1 = json.dumps(nas, cls=AlchemyEncoder)
            return jsonstr1
        elif request.method == 'GET':
            json_data = request.get_json()
            aux = Nas.query.filter_by(id=json_data['id']).first()
            jsonstr1 = json.dumps(aux, cls=AlchemyEncoder)
            return jsonstr1
    else:
        return '404'





# Class Principal

@app.route('/openvpnServer', methods=['POST', 'GET'])
@cross_origin()
def openvpnobject():
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        if request.method == 'POST':
            json_data = request.get_json()

            host = json_data['host']
            port = json_data['port']
            name = json_data['name']
            password = json_data['password']
            show_disconnect = json_data['show_disconnect']
            maxRegister = json_data['maxRegister']
            clientActive = json_data['clientActive']
            clientRegister = json_data['clientRegister']
            httpPort = json_data['httpPort']
            ram = json_data['ram']
            cpu = json_data['cpu']
            hostInternal = json_data['hostInternal']

            vpnServer = VpnServer(ram=ram, cpu=cpu, hostInternal=hostInternal, host=host, httpPort=httpPort, port=port, name=name, password=password, show_disconnect=show_disconnect,
                                  maxRegister=maxRegister, clientActive=clientActive, clientRegister=clientRegister)
            db.session.add(vpnServer)
            # db.session.commit()
            db.session.flush()
            db.session.refresh(vpnServer)
            db.session.commit()
            jsonstr1 = json.dumps(vpnServer, cls=AlchemyEncoder)
            return jsonstr1
        elif request.method == 'GET':
            # json_data = request.get_json()
            # aux = VpnServer.query.filter_by(id=json_data['id']).first()
            # jsonstr1 = json.dumps(aux, cls=AlchemyEncoder)
            aux = getServerInformation()
            listRet = []
            for value in aux:
                print(aux[value])
                aux[value]['_sa_instance_state'] = None
                try:
                    aux[value]['state']['local_ip'] = str(aux[value]['state']['local_ip'])
                    if aux[value]['state']['remote_ip'] is not None:
                        aux[value]['state']['remote_ip'] = str(aux[value]['state']['remote_ip'])
                except:
                    print('no found')
                try:
                    aux[value]['version'] = str(aux[value]['version'])
                except:
                    print('no found')
                try:
                    aux[value]['state']['up_since'] = int(round(aux[value]['state']['up_since'].timestamp()))
                    print(aux[value]['state']['up_since'])
                except:
                    print('no found')
                count = 0
                try:
                    for val in aux[value]['sessions']:
                        count+=1
                        aux[value]['sessions'][val]['connected_since'] = int(
                            round(aux[value]['sessions'][val]['connected_since'].timestamp()))
                        aux[value]['sessions'][val]['last_seen'] = int(
                            round(aux[value]['sessions'][val]['last_seen'].timestamp()))
                        aux[value]['sessions'][val]['local_ip'] = str(aux[value]['sessions'][val]['local_ip'])
                        aux[value]['sessions'][val]['remote_ip'] = str(aux[value]['sessions'][val]['remote_ip'])
                except:
                    print('no found')
                aux[value]['sessions'] = count
                # print(aux[value]['state']['local_ip'])

                listRet.append(aux[value])
            print(listRet)
            jsonstr1 = json.dumps(listRet, default=lambda o: o.__dict__,
                                  sort_keys=True)
            return jsonstr1
    else:
        return '404'




# <class 'str'>
@app.route('/packSubcrition', methods=['POST', 'GET'])
@cross_origin()
def packSubcrition():
    content_type = request.headers.get('Content-Type')
    print('rr')
    if (content_type == 'application/json'):
        if request.method == 'POST':
            json_data = request.get_json()
            packSubcription = None
            try:
                packSubcription = PackSubcription.query.filter_by(id=json_data['id']).first()
            except:
                packSubcription = None
                print('no found error')

            if packSubcription is None:
                nombre = json_data['nombre']
                descripcion = json_data['descripcion']
                typePack = json_data['typePack']
                dataUsage = json_data['dataUsage']
                price = json_data['price']
                tax = json_data['tax']
                day = json_data['day']
                prO = json_data['prO']
                taO = json_data['taO']
                status = True
                principal = json_data['principal']
                packSubcription = PackSubcription(
                		nombre=nombre,
                		descripcion=descripcion,
                		typePack=typePack,
                		dataUsage=dataUsage,
                		price=price,
                		tax=tax,
                		day=day,
                		prO=prO,
                		taO=taO,
                		status=status,
                        principal=principal
            )
                db.session.add(packSubcription)
                db.session.flush()
                db.session.refresh(packSubcription)
                db.session.commit()
                jsonstr1 = json.dumps(packSubcription, cls=AlchemyEncoder)
                return jsonstr1 
            else:
                aux = PackSubcription.query.filter_by(id=json_data['id']).first()
                for key in json_data:
                    aux[key] = json_data[key]
                db.session.flush()
                db.session.refresh(aux)
                db.session.commit()
                jsonstr1 = json.dumps(aux, cls=AlchemyEncoder)
                return jsonstr1 

        elif request.method == 'GET':
            json_data = request.get_json()
            packSubcription = None
            if json_data['id'] is None:
                aux = PackSubcription.query.all()
                jsonstr1 = json.dumps(aux, cls=AlchemyEncoder)
                return jsonstr1
            else:
                aux = PackSubcription.query.filter_by(id=json_data['id']).first()
                jsonstr1 = json.dumps(aux, cls=AlchemyEncoder)
                return jsonstr1
            

    else:
        return '404'

@app.route('/planClient', methods=['POST', 'GET'])
@cross_origin()
def setPlanClient():
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        json_data = request.get_json()
        if request.method == 'POST':
            
            client = Client.query.filter_by(user=json_data['user']).first()
            auxP = PackSubcription.query.filter_by(id=json_data['id']).first()

            print(client)
            if client is not None and auxP is not None:
                if client.idPackPrincipal is not None and auxP.principal == True:
                    clpack = ClientPackSubcription.query.filter_by(userClient=json_data['user'], idPack=auxP.id).first()
                    anotherPack = PackSubcription.query.filter_by(id=json_data['anotherID']).first()
                    if clpack is not None and anotherPack is not None:
                        clpack.idPack = anotherPack.id
                        db.session.flush()
                        db.session.refresh(clpack)
                        db.session.commit()

                        client.idPackPrincipal = anotherPack.id
                        client.DataMaxUse -=auxP.dataUsage
                        client.DataMaxUse +=anotherPack.dataUsage
                        db.session.flush()
                        db.session.refresh(client)
                        db.session.commit()
                        client.sta = 'change'
                        jsonstr1 = json.dumps(client, cls=AlchemyEncoder)
                        return jsonstr1
                    else:
                        return 'Error'

                elif client.idPackPrincipal is None  and auxP.principal == True:
                    clientPackSubcription = ClientPackSubcription(userClient=client.user, idPack=auxP.id,type=json_data['type'],
                    exp=client.fechaExpiracion, isTemporary=json_data['isTemporary'])
                    db.session.add(clientPackSubcription)
                    db.session.flush()
                    db.session.refresh(clientPackSubcription)
                    db.session.commit()

                    client.idPackPrincipal = auxP.id
                    client.DataMaxUse +=1
                    client.DataMaxUse +=auxP.dataUsage
                    db.session.flush()
                    db.session.refresh(client)
                    db.session.commit()
                    client.sta = 'newPack'
                    jsonstr1 = json.dumps(client, cls=AlchemyEncoder)
                    return jsonstr1
                elif client.idPackPrincipal is not None  and auxP.principal == False:
                    clientPackSubcription = ClientPackSubcription(userClient=client.user, idPack=auxP.id,type=json_data['type'],
                    exp=client.fechaExpiracion, isTemporary=json_data['isTemporary'])
                    db.session.add(clientPackSubcription)
                    db.session.flush()
                    db.session.refresh(clientPackSubcription)
                    db.session.commit()


                    client.DataMaxUse +=auxP.dataUsage
                    db.session.flush()
                    db.session.refresh(client)
                    db.session.commit()
                    client.sta = 'extra'
                    jsonstr1 = json.dumps(client, cls=AlchemyEncoder)
                    return jsonstr1
                else:
                    return 'Error'


                print()
            else:
                return None
        elif request.method == 'GET':
            datetime_object = datetime.now()
            aux = None
            try:
                if json_data['status1'] == 'user':
                    aux = ClientPackSubcription.query.filter_by(userClient=json_data['user']).first()
                elif json_data['status1'] == 'one':
                    aux = ClientPackSubcription.query.filter_by(userClient=json_data['user'],idPack=json_data['id']).first()
                else:
                    aux = PackSubcription.query.all()

            except:
                aux = None
                print('no found error')
                return None
            jsonstr1 = json.dumps(aux, cls=AlchemyEncoder)
            return jsonstr1

    else:
        return '404'


@app.route('/processPay', methods=['POST', 'GET'])
@cross_origin()
def processPay():
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        json_data = request.get_json()
        listPlan = []
        if request.method == 'POST':

            client = Client.query.filter_by(user=json_data['user']).first()

            packSub = ClientPackSubcription.query.filter_by(userClient=json_data['user']).all()
            totalO = 0
            taxO = 0
            total = 0
            tax = 0
            princi = None
            detailInvoice = []
            if client is not None and packSub is not None:
                for key in packSub:
                    subcri = PackSubcription.query.filter_by(id=key.idPack).first()
                    totalO += subcri.prO
                    taxO += subcri.taO

                    total += subcri.price
                    tax += subcri.tax
                    listPlan.append(subcri)
                invoice = Invoice(
                    detail=json_data['detail'],
                    idClient=json_data['user'],
                    price=total,
                    tax=tax,
                    prO=totalO,
                    taO=taxO,
                    cruce=json_data['cruce']
                )
                db.session.add(invoice)
                db.session.flush()
                db.session.refresh(invoice)
                db.session.commit()
                print(invoice.id)
                for key in listPlan:

                    detInv = DetailInvoice(

                        nombre=key.nombre,
                        descripcion=key.descripcion,
                        typePack=key.typePack,
                        dataUsage=key.dataUsage,
                        price=key.price,
                        tax=key.tax,
                        day=key.day,
                        prO=key.prO,
                        taO=key.taO,
                        idInvoice=invoice.id
                        )
                    db.session.add(detInv)
                    db.session.flush()
                    db.session.refresh(detInv)
                    db.session.commit()
                    detailInvoice.append(detInv)
                    packSubEdit = ClientPackSubcription.query.filter_by(userClient=json_data['user'], idPack= key.id).first()
                    packSubEdit.exp = invoice.fechaCreacion+timedelta(days=key.day)
                    db.session.flush()
                    db.session.refresh(packSubEdit)
                    db.session.commit()
                    if key.principal == True:
                        princi = packSubEdit
                client.fechaExpiracion = princi.exp
                db.session.flush()
                db.session.refresh(client)
                db.session.commit()
                varia = {
                    "invoice":invoice,
                    "detail": detailInvoice
                }
                jsonstr1 = json.dumps(varia, cls=AlchemyEncoder)
                return jsonstr1







        elif request.method == 'GET':
            print('hola')
            datetime_object = datetime.now()
            invoList = None

            try:
                invoList = Invoice.query.filter_by(idClient=json_data['user']).all()

            except Exception as e:
                print(e)
                print('no found error')
                return None
            jsonstr1 = json.dumps(invoList, cls=AlchemyEncoder)
            return jsonstr1

    else:
        return '404'


@app.route('/client', methods=['POST', 'GET'])
@cross_origin()
def client():
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        if request.method == 'POST':
            json_data = request.get_json()
            datetime_object = datetime.now()
            aux = None
            try:
                aux = Client.query.filter_by(user=json_data['user']).first()
            except:
                aux = None
                print('no found error')
            print(aux)
            if aux is not None and json_data['status1'] == 'edit':
                print('Existe')
                for key in json_data:
                    if key != 'status1':
                        aux[key] = json_data[key]
                aux.fechaMod = datetime_object
                aux.userMod = session['user']
                db.session.flush()
                db.session.refresh(aux)
                db.session.commit()
                jsonstr1 = json.dumps(aux, cls=AlchemyEncoder)
                return jsonstr1
                
                # return 'ErrorUserExist'
            else:
                idVPNServ = None
                if json_data['idvpnServerDefault'] is not None:
                    idVPNServ = json_data['idvpnServerDefault']
                else:
                    idVPNServ = 0
                user = json_data['user']
                nombre = json_data['nombre']
                apellido = json_data['apellido']
                documento = json_data['documento']
                fechaNacimiento = json_data['fechaNacimiento']
                status = True
                password = encrypt.encrypt(json_data['password'])
                FechaCreacion = datetime_object
                fechaExpiracion = datetime_object
                fechaMod = datetime_object
                userMod = session['user']
                DataMaxUse = -1
                idPackPrincipal = json_data['idPackPrincipal']
                typeClient = 'CLI'
                userAdm = session['user']
                idvpnServerDefault = idVPNServ
                radChe = Radcheck(username=json_data['user'],
                                  attribute='Cleartext-Password',
                                  op=':=',
                                  value=json_data['password'],
                                  maxDataUsage=-1,
                                  status=True,
                                  expDate=datetime_object)

                db.session.add(radChe)
                db.session.flush()
                db.session.refresh(radChe)
                db.session.commit()

                clien = Client(
                user=user,
                nombre=nombre,
                apellido=apellido,
                documento=documento,
                fechaNacimiento=fechaNacimiento,
                status=status,
                password=password,
                FechaCreacion=FechaCreacion,
                fechaExpiracion=fechaExpiracion,
                DataMaxUse=DataMaxUse,
                idVPN=radChe.id,
                fechaMod=fechaMod,
                idPackPrincipal=idPackPrincipal,
                typeClient=typeClient,
                userAdm=userAdm,
                userMod=userMod,
                idvpnServerDefault=idvpnServerDefault
                )
                vpnServ = VpnServer.query.filter_by(id=idvpnServerDefault).first()
                if vpnServ is not None:
                    api_url = "http://"+vpnServ.host+':'+str(vpnServ.httpPort)+"/createClient"
                    todo = {"user": user, "select": "1", "key": encrypt.encrypt('admin1234')}
                    headers = {"Content-Type": "application/json"}
                    response = requests.post(api_url, data=json.dumps(todo), headers=headers)
                    vari = response.json()
                    print(vari)
                db.session.add(clien)
                db.session.flush()
                db.session.refresh(clien)
                db.session.commit()
                jsonstr1 = json.dumps(clien, cls=AlchemyEncoder)
                return jsonstr1
        elif request.method == 'GET':
            json_data = request.get_json()
            aux = None
            if json_data['user'] is None:
                aux = Client.query.all()
                jsonstr1 = json.dumps(aux, cls=AlchemyEncoder)
                return jsonstr1
            else:
                aux = Client.query.filter_by(user=json_data['user']).first()
                jsonstr1 = json.dumps(aux, cls=AlchemyEncoder)
                return jsonstr1
            # aux = Client.query.all()
            # jsonstr1 = json.dumps(aux, cls=AlchemyEncoder)
            # return jsonstr1
    else:
        return '404'






# return render_template("index.html",posts=posts)

@app.route('/openvpn-monitor-remove/', methods=['POST'])
@cross_origin()
def openvpnmonitorremove():
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        js = request.get_json()
        print(type(js))
        print(js)
        print(js.get('vpn_ip'))

        x = js

        print('ho')

        vpn_id = x['vpn_ip']
        ip = x['ip']
        port = x['port']
        client_id = x['client_id']
        print('Ya paso')
        args = get_args()
        wsgi = False
        aux = main(vpn_id=vpn_id, ip=ip, port=port, client_id=client_id)
        jsonStr = json.dumps(aux)
        # jsonStr2 = json.loads(aux)
        debug("{0!s}".format(aux))
        debug("{0!s}".format(jsonStr))
        # debug("{0!s}".format(jsonStr2))
        # return jsonify(jsonStr)
        return aux

    else:
        return 'Content-Type not supported!'


if __name__ == '__main__':
    class args(object):
        debug = False
        config = './openvpn-monitor.conf'


    # args = get_args()
    # wsgi = False
    # main()
    with app.app_context():
        db.create_all()  # <--- create db object.
        db.create_all(bind=['vpnManager'])
    app.run(host='0.0.0.0', port=8000, debug=True)
