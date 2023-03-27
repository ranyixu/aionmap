import asyncio
import collections.abc
import os
import re
import shlex
import signal
import sys
from concurrent.futures import FIRST_COMPLETED, ALL_COMPLETED
from libnmap.parser import NmapParser

regex_warning = re.compile('^Warning: .*', re.IGNORECASE)
regex_nmap_version = re.compile('Nmap version (?:([0-9]*)\.([0-9]*))?')
_regex_pid = re.compile(r"\s*(\d+)+\s*(\d+)\s*")

class PortScannerBase(object):
    def __init__(self, nmap_search_path=('nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap', '/opt/local/bin/nmap')):
        self._nmap_path = ''                # nmap path
        self._scan_result = {}
        self._nmap_version_number = 0       # nmap version number
        self._nmap_subversion_number = 0    # nmap subversion number
        self._nmap_search_path = nmap_search_path

    async def _ensure_nmap_path_and_version(self):
        if self._nmap_path:
            return

        async def _test_nmap_path(nmap_path):
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(nmap_path, '-V', stdout=asyncio.subprocess.PIPE)
                while not proc.stdout.at_eof():
                    line = (await proc.stdout.readline()).decode('utf-8')
                    match_res = regex_nmap_version.match(line)
                    if match_res is None:
                        continue

                    # extract for version number
                    ver_major, ver_sub = None, None
                    re_groups = match_res.groups()
                    if len(re_groups) >= 2:
                        ver_major, ver_sub = re_groups[0], re_groups[1]
                        if ver_major:
                            ver_major = int(ver_major)
                        if ver_sub:
                            ver_sub = int(ver_sub)
                    return True, ver_major, ver_sub
            except:
                pass
            finally:
                if proc:
                    try:
                        proc.terminate()
                    except ProcessLookupError:
                        pass
                    await proc.wait()
            return False, None, None

        for p in self._nmap_search_path:
            found, ver_major_, ver_sub_ = await _test_nmap_path(p)
            if not found:
                continue

            self._nmap_path = p
            self._nmap_version_number = ver_major_,
            self._nmap_subversion_number = ver_sub_
            return

        raise NmapError('nmap program was not found in path')

    async def nmap_version(self):
        await self._ensure_nmap_path_and_version()
        return self._nmap_version_number, self._nmap_subversion_number

    async def listscan(self, hosts='127.0.0.1', dns_lookup=True, sudo=False,  sudo_passwd=None):
        await self._ensure_nmap_path_and_version()
        nmap_args = self._get_scan_args(hosts, None, arguments='-sL' if dns_lookup else '-sL -n')
        return (await self._scan_proc(*nmap_args, sudo=sudo, sudo_passwd=sudo_passwd))

    def analyse_nmap_xml_scan(self, nmap_xml_output=None, nmap_err='', nmap_err_keep_trace='', nmap_warn_keep_trace=''):
        try:
            report = NmapParser.parse_fromstring(nmap_xml_output)
            report.__dict__['errors'] = nmap_err_keep_trace
            report.__dict__['warnings'] = nmap_warn_keep_trace
            return report
        except Exception:
            if nmap_err:
                raise NmapError(nmap_err)
            else:
                raise NmapError(nmap_xml_output)

    async def _scan_proc(self, *nmap_args, sudo=False, sudo_passwd=None):
        proc = None
        try:
            if sudo:
                if not sudo_passwd:
                    raise NmapError("sudo must with 'sudo_passwd' argument")
                proc = await asyncio.create_subprocess_exec(
                    'sudo', '-S', '-p', 'nmap sudo prompt: ',
                    self._nmap_path, *nmap_args,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    self._nmap_path, *nmap_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            nmap_output, nmap_err = await proc.communicate(None if not sudo else (sudo_passwd.encode()+b"\n"))
            if nmap_err:
                if sudo and nmap_err.strip() == b'nmap sudo prompt: ':
                    nmap_err = b''
        except:
            raise
        else:
            if nmap_err:
                nmap_err = nmap_err.decode('utf8')
            if nmap_output:
                nmap_output = nmap_output.decode('utf8')

            nmap_err_keep_trace = []
            nmap_warn_keep_trace = []
            if nmap_err:
                for line in nmap_err.split(os.linesep):
                    if not line:
                        continue
                    rgw = regex_warning.search(line)
                    if rgw is not None:
                        nmap_warn_keep_trace.append(line + os.linesep)
                    else:
                        nmap_err_keep_trace.append(nmap_err)

            return self.analyse_nmap_xml_scan(
                nmap_xml_output=nmap_output,
                nmap_err=nmap_err,
                nmap_err_keep_trace=nmap_err_keep_trace,
                nmap_warn_keep_trace=nmap_warn_keep_trace
            )
        finally:
            if proc:
                try:
                    await self._terminate_proc(proc, sudo_passwd)
                except ProcessLookupError:
                    pass
                await proc.wait()

    async def _terminate_proc(self, proc, sudo_passwd=None):
        try:
            proc.terminate()
            return
        except LookupError:
            return
        except:
            if not sudo_passwd:
                raise
        children = await self._find_process_by_ppid(proc.pid)
        for pid in children:
            await self._terminate_proc_by_sudo(pid, sudo_passwd)
        await self._terminate_proc_by_sudo(proc.pid, sudo_passwd)

    def _terminate_proc_by_sudo(self, pid, sudo_passwd, signo=15):
        proc_kill = await asyncio.create_subprocess_exec(
            'sudo', '-S', '-p', 'nmap sudo prompt: ', 'kill', '-%s' % signo, str(pid),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc_kill.communicate(sudo_passwd.encode() + b"\n")
        await proc_kill.wait()

    async def _find_process_by_ppid(self, ppid):
        proc = await asyncio.create_subprocess_exec(
            "ps", "-efo", "pid,ppid", "--ppid", str(ppid),
            stdout=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        await proc.wait()

        first_line = True
        pid_list = []
        for line in stdout.decode('utf-8').splitlines():
            if first_line:
                first_line = False
                continue
            match_res = _regex_pid.match(line)
            if not match_res:
                continue
            groups = match_res.groups()
            if len(groups) < 2:
                continue
            pid_list.append(int(groups[0]))
        return pid_list

    def _get_scan_args(self, hosts, ports, arguments):
        assert isinstance(hosts, (str, collections.abc.Iterable)), \
            'Wrong type for [hosts], should be a string or Iterable [was {0}]'.format(type(hosts))
        assert isinstance(ports, (str, collections.abc.Iterable, type(None))), \
            'Wrong type for [ports], should be a string or Iterable [was {0}]'.format(type(ports))  # noqa
        assert isinstance(arguments, str), \
            'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))  # noqa

        if not isinstance(hosts, str):
            hosts = ' '.join(hosts)
        assert all(_ not in arguments for _ in ('-oX', '-oA')), 'Xml output can\'t be redirected from command line'
        if ports and not isinstance(ports, str):
            ports = ','.join(str(port) for port in ports)
        hosts_args = shlex.split(hosts)
        scan_args = shlex.split(arguments)
        return ['-oX', '-'] + hosts_args + ['-p', ports] * bool(ports) + scan_args


class PortScanner(PortScannerBase):
    async def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False, sudo_passwd=None):
        await self._ensure_nmap_path_and_version()
        scan_result = await self._scan_proc(*(self._get_scan_args(hosts, ports, arguments)), sudo=sudo, sudo_passwd=sudo_passwd)
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
        def __init__(self, scanner, hosts, args, batch_count=3, sudo=False, sudo_passwd=None):
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
            self.sudo_passwd = sudo_passwd

        def _done_fu_generator(self, done_futs):
            await done_futs

        def _get_result(self):
            fu = self._done_fut_gen.send(None)
            exception = fu.exception()
            return exception if exception is not None else fu.result()

        async def __aiter__(self):
            return self

        def _ip_generator(self, ip_list):
            await ip_list

        def _fill_future(self):
            try:
                while len(self._futs) < self._batch_count:
                    self._futs.add(
                        asyncio.ensure_future(
                            self._scanner._scan_proc(
                                self._ip_gen.send(None), *self._args, sudo=self.sudo, sudo_passwd=self.sudo_passwd
                            )
                        )
                    )
            except StopIteration:
                self._stop_ip_gen = True

        async def __anext__(self):
            if not self._started:
                self._started = True
                list_scan = await self._scanner.listscan(
                    self._hosts, False,
                    sudo=self.sudo, sudo_passwd=self.sudo_passwd
                )
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
            try:
                done, pending = await asyncio.wait(self._futs, return_when=FIRST_COMPLETED)
            except asyncio.CancelledError:
                cancel_futs = []
                for fut in self._futs:
                    if not fut.done():
                        fut.cancel()
                        cancel_futs.append(fut)
                if cancel_futs:
                    await asyncio.wait(cancel_futs, return_when=ALL_COMPLETED)
                raise
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

        def scan(self, hosts, ports=None, arguments="-sV", batch_count=3, sudo=False, sudo_passwd=None):
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

