# aionmap
> A python aysncio package for nmap.

## install
> just run **python3 setup.py**

## usage
### scan result
The scan result parsed by [libnmap.parser.NmapParser](https://libnmap.readthedocs.io/en/latest/parser.html#module-libnmap.parser), so [python-libnmap](https://pypi.org/project/python-nmap/) is required. and the parsed-result is [libnmap.objects.NmapReport](https://libnmap.readthedocs.io/en/latest/objects/nmapreport.html). 

### PortScanner
A port scanner similar to python-nmap PortScanner. It is run in a process and wait until process exit with **yield from** or **await**.
eg:
```python
import aionmap
import asyncio

async def main():
    scanner =  aionmap.PortScanner()
    print(await scanner.nmap_version())
    result = await scanner.listscan('192.168.0.0/24', False)
    print(result)
    result = await scanner.scan('localhost', None, '-sS -sV -n', sudo=True, sudo_passwd='xxx')
    print(result)
    
if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
```
### PortScannerYield
A port scanner similar to python-nmap PortScannerYield,  but **async for** instead. It can only run with environment where Python  version greater than 3.5. The scanner run with multi processes at the same time, default is 3 processes, you can control it by argument **batch_count** when call function **PortScannerYield.scan**.
eg:
```python
import asyncio

import aionmap


async def main():
    scanner =  aionmap.PortScannerYield()
    async for result in scanner.scan('192.168.0.0/24', '80,22', '-sS -n --open', sudo=True, sudo_passwd='xxx'):
        if isinstance(result, Exception):
            print("error")
        else:
            print(result)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
```

