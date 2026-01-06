#!/usr/bin/python3
# © 2024 Michal Trojnara
# This script downloads Microsoft code signing certificates
# Tor is required for this script to work
# Redirect the script output to a PEM file

from sys import stderr
from time import sleep
from csv import reader
from requests import get
from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor
from re import search

def download_cert(hash):
    for attempt in range(10):
        if attempt > 0:
            sleep(10)
        try:
            creds = f'{attempt}{hash}:{attempt}{hash}'
            proxies = dict(https=f'socks5://{creds}@127.0.0.1:9050')

            url = f'https://crt.sh/?sha1={hash}&match=='
            resp = get(url, proxies=proxies)
            resp.raise_for_status()

            m = search(r'\bid=(\d+)\b', resp.content.decode('ascii', 'replace'))
            id = m.group(1)

            url = f'https://crt.sh/?d={id}'
            resp = get(url, proxies=proxies)
            resp.raise_for_status()

            print('.', file=stderr, end='')
            stderr.flush()
            return resp.content.decode('utf-8', 'replace')
        except Exception as e:
            print(f'\n{url} attempt {attempt}: {e}', file=stderr)
    print('\nGiving up on', hash, file=stderr)

resp = get('https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSV')
resp.raise_for_status()
lines = resp.content.decode('utf-8').splitlines()[1:]
hashes = [row[4] for row in reader(lines)
    if row[0] != 'Disabled'
        or row[4] == 'F38406E540D7A9D90CB4A9479299640FFB6DF9E224ECC7A01C0D9558D8DAD77D']
with ThreadPoolExecutor(max_workers=10) as executor:
    certs = executor.map(download_cert, hashes)
for cert in certs:
    if cert is not None:
        print(cert)
print('\nDone', file=stderr)
