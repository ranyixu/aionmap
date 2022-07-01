import asyncio
import collections.abc
import os
import re
import shlex
import subprocess
from xml.etree import ElementTree as ET
import sys
from concurrent.futures import FIRST_COMPLETED
from libnmap.parser import NmapParser

regex_warning = re.compile('^Warning: .*', re.IGNORECASE)
regex_nmap_version = re.compile('Nmap version [0-9]*\.[0-9]*[^ ]* \( https?://.* \)')
regex_version = re.compile('[0-9]+')
regex_subversion = re.compile('\.[0-9]+')

class PortScannerBase(object):
    def __init__(self, nmap_search_path=('nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap', '/opt/local/bin/nmap')):
        self._nmap_path = ''                # nmap path
        self._scan_result = {}
        self._nmap_version_number = 0       # nmap version number
        self._nmap_subversion_number = 0    # nmap subversion number
        self._nmap_search_path = nmap_search_path
    
    @asyncio.coroutine
    def _ensure_nmap_path_and_version(self):
        if self._nmap_path:
            return
        is_nmap_found = False
        
        for nmap_path in self._nmap_search_path:
            proc = None
            try:
                proc = yield from asyncio.create_subprocess_exec(nmap_path, '-V', stdout = asyncio.subprocess.PIPE)
                while True:
                    line = yield from proc.stdout.readline()
                    line = line.decode('utf8')
                    if line and regex_nmap_version.match(line) is not None:
                        is_nmap_found = True
                        self._nmap_path = nmap_path
                        
                        # Search for version number
                        rv = regex_version.search(line)
                        rsv = regex_subversion.search(line)
        
                        if rv is not None and rsv is not None:
                            # extract version/subversion
                            self._nmap_version_number = int(line[rv.start():rv.end()])
                            self._nmap_subversion_number = int(
                                line[rsv.start()+1:rsv.end()]
                            )
                        break
                    if proc.stdout.at_eof():
                        break
            except:
                pass
            else:
                if is_nmap_found:
                    break
            finally:
                if proc:
                    try:
                        proc.terminate()
                    except ProcessLookupError:
                        pass
                    yield from proc.wait()
        if not is_nmap_found:
            raise NmapError('nmap program was not found in path')
            
    @asyncio.coroutine
    def nmap_version(self):
        yield from self._ensure_nmap_path_and_version()
        return (self._nmap_version_number, self._nmap_subversion_number)   

    @asyncio.coroutine
    def listscan(self, hosts='127.0.0.1', dns_lookup = True, sudo=False,  sudo_passwd=None):
        yield from self._ensure_nmap_path_and_version()
        nmap_args = self._get_scan_args(hosts, None, arguments = '-sL' if dns_lookup else '-sL -n')
        return (yield from self._scan_proc(*nmap_args, sudo=sudo, sudo_passwd=sudo_passwd))
    
    def analyse_nmap_xml_scan(self, nmap_xml_output=None, nmap_err='', nmap_err_keep_trace='', nmap_warn_keep_trace=''):

        try:
            report = NmapParser.parse_fromstring(nmap_xml_output)
            report.__dict__['errors'] = nmap_err_keep_trace
            report.__dict__['warnings'] = nmap_warn_keep_trace
            return report
        except Exception:
            if len(nmap_err)>0:
                raise NmapError(nmap_err)
            else:
                raise NmapError(nmap_xml_output)


    @asyncio.coroutine
    def _scan_proc(self, *nmap_args, sudo=False, sudo_passwd=None):
        proc = None
        try:
            if sudo:
                if not sudo_passwd:
                    raise NmapError("sudo must with 'sudo_passwd' argument")
                proc = yield from asyncio.create_subprocess_exec('sudo', '-S', '-p', 'xxxxx', self._nmap_path, *nmap_args, stdin=asyncio.subprocess.PIPE,
                                                                 stdout = asyncio.subprocess.PIPE,
                                                                 stderr = asyncio.subprocess.PIPE)
            else:
                proc = yield from asyncio.create_subprocess_exec(self._nmap_path, *nmap_args, stdout = asyncio.subprocess.PIPE,
                                                            stderr = asyncio.subprocess.PIPE)
            nmap_output, nmap_err = yield from proc.communicate(None if not sudo else (sudo_passwd.encode()+b"\n"))
            if nmap_err:
                if sudo and nmap_err.strip() == b'xxxxx':
                    nmap_err=b''
        except:
            raise
        finally:
            if proc:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
                yield from proc.wait()
        if nmap_err:
            nmap_err = nmap_err.decode('utf8')
        if nmap_output:
            nmap_output = nmap_output.decode('utf8')
            
        nmap_err_keep_trace = []
        nmap_warn_keep_trace = []
        if len(nmap_err) > 0:
            for line in nmap_err.split(os.linesep):
                if len(line) > 0:
                    rgw = regex_warning.search(line)
                    if rgw is not None:
                        # sys.stderr.write(line+os.linesep)
                        nmap_warn_keep_trace.append(line+os.linesep)
                    else:
                        # raise NmapError(nmap_err)
                        nmap_err_keep_trace.append(nmap_err)

        return self.analyse_nmap_xml_scan(
            nmap_xml_output=nmap_output,
            nmap_err=nmap_err,
            nmap_err_keep_trace=nmap_err_keep_trace,
            nmap_warn_keep_trace=nmap_warn_keep_trace
        )
        
    def _get_scan_args(self, hosts, ports, arguments):
        assert isinstance(hosts, (str, collections.abc.Iterable)), 'Wrong type for [hosts], should be a string or Iterable [was {0}]'.format(type(hosts))
        assert isinstance(ports, (str, collections.abc.Iterable, type(None))), 'Wrong type for [ports], should be a string or Iterable [was {0}]'.format(type(ports))  # noqa
        assert isinstance(arguments, str), 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))  # noqa
        
        if not isinstance(hosts, str):
            hosts = ' '.join(hosts)
        assert all(_ not in arguments for _ in ('-oX', '-oA')), 'Xml output can\'t be redirected from command line'
        if ports and not isinstance(ports, str):
            ports = ','.join(str(port) for port in ports)
        hosts_args = shlex.split(hosts)
        scan_args = shlex.split(arguments)
        return ['-oX', '-'] + hosts_args + ['-p', ports] * bool(ports) + scan_args
        
class PortScanner(PortScannerBase):
    @asyncio.coroutine
    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False, sudo_passwd=None):
        yield from self._ensure_nmap_path_and_version()
        scan_result = yield from self._scan_proc(*(self._get_scan_args(hosts, ports, arguments)), sudo=sudo, sudo_passwd=sudo_passwd)
        self._scan_result = scan_result
        return scan_result
        
    def __getitem__(self, host):
        """
        returns a host detail
        """
        return self._scan_result['scan'][host]

gt_py35 = (sys.version_info.major == 3 and sys.version_info.minor >= 5) or sys.version_info.major > 3
if gt_py35:
    class PortScannerIterable(object):
        def __init__(self, scanner, hosts, args, batch_count = 3, sudo = False, sudo_passwd=None):
            self._scanner = scanner
            self._hosts = hosts
            self._args = args
            self._futs = set()
            self._batch_count = batch_count
            self._stop_ip_gen = False
            self._done_fut_gen = None
            self._stopped = False
            self._started = False
            self.sudo = sudo
            self.sudo_passwd=sudo_passwd
            
        def _done_fu_generator(self, done_futs):
            yield from done_futs
        
        def _get_result(self):
            fu = self._done_fut_gen.send(None)
            exception = fu.exception()
            return exception if exception is not None else fu.result()
        
        async def __aiter__(self):
            return self
        
        def _ip_generator(self, ip_list):
            yield from ip_list
        
        def _fill_future(self):
            try:
                while len(self._futs) < self._batch_count:
                    self._futs.add(asyncio.ensure_future(self._scanner._scan_proc(self._ip_gen.send(None), *self._args, sudo=self.sudo, sudo_passwd=self.sudo_passwd)))
            except StopIteration:
                self._stop_ip_gen = True
        
        async def __anext__(self):
            if not self._started:
                self._started = True
                list_scan = await self._scanner.listscan(self._hosts, False, sudo=self.sudo, sudo_passwd=self.sudo_passwd)
                if not list_scan:
                    return
                ip_list = [i.address for i in list_scan.hosts]
                if not ip_list:
                    raise StopAsyncIteration()
                self._ip_gen = self._ip_generator(ip_list)
                self._fill_future()
            elif self._done_fut_gen:
                try:
                    return self._get_result()
                except:
                    self._done_fut_gen = None
                    if self._stopped:
                        raise StopAsyncIteration()
            done, pending = await asyncio.wait(self._futs, return_when = FIRST_COMPLETED)
            self._done_fut_gen = self._done_fu_generator(done)
            if not pending and self._stop_ip_gen:
                self._stopped = True
            else:
                self._futs = pending
            if not self._stop_ip_gen:
                self._fill_future()
                if not self._futs and not pending:
                    self._stopped = True
            return self._get_result()
        
    class PortScannerYield(PortScannerBase):
        
        def scan(self, hosts, ports, arguments, batch_count=3, sudo=False, sudo_passwd=None):
            args = self._get_scan_args('', ports, arguments)
            return PortScannerIterable(self, hosts, args, batch_count, sudo, sudo_passwd)

    
class NmapError(Exception):
    """
    Exception error class for PortScanner class

    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'NmapError exception {0}'.format(self.value)
    
