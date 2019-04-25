#-*- coding:utf-8 -*-
'''
Created on 2018-05-23

@author: ranyixu
'''
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
    
