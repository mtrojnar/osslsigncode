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

def download_cert(hash):
    for attempt in range(10):
        if attempt > 0:
            sleep(10)
        try:
            creds = f'{attempt}{hash}:{attempt}{hash}'
            resp = get(f'https://crt.sh/?d={hash}',
                proxies=dict(https=f'socks5://{creds}@127.0.0.1:9050'))
            resp.raise_for_status()
            print('.', file=stderr, end='')
            stderr.flush()
            return resp.content.decode('utf-8')
        except RequestException as e:
            print(f'\nAttempt {attempt}: {e}', file=stderr)
    print('\nGiving up on', hash, file=stderr)

resp = get('https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV')
resp.raise_for_status()
lines = resp.content.decode('utf-8').splitlines()[1:]
hashes = [row[4] for row in reader(lines)
    if row[0] != 'Disabled'
        or row[4] == 'F38406E540D7A9D90CB4A9479299640FFB6DF9E224ECC7A01C0D9558D8DAD77D']
with ThreadPoolExecutor(max_workers=20) as executor:
    certs = executor.map(download_cert, hashes)
for cert in certs:
    if cert is not None:
        print(cert)
print('\nDone', file=stderr)
