#-*- coding:utf-8 -*-
'''
Created on 2018-05-23

@author: ranyixu
'''
import aionmap
import asyncio

async def main():
    scanner =  aionmap.PortScanner()
    print(await scanner.nmap_version())
    result = await scanner.listscan('192.168.0.0/24', False)
    print(result)
    result = await scanner.scan('localhost', None, '-sS -sV -n')
    print(result)
    
if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())