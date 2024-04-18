#!/usr/bin/python3
# © 2024 Michal Trojnara
# This script downloads Microsoft code signing certificates
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
            resp = get('https://crt.sh/?d=' + hash)
            resp.raise_for_status()
            print('.', file=stderr, end='')
            stderr.flush()
            return resp.content.decode('utf-8')
        except RequestException as e:
            print(f'\n{e}', file=stderr)
    print('\nGiving up on', hash, file=stderr)

resp = get('https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV')
resp.raise_for_status()
lines = resp.content.decode('utf-8').splitlines()
hashes = [row[4] for row in reader(lines)
    if row[0] != 'Disabled' and 'Code Signing' in row[5].split(';')]
with ThreadPoolExecutor(max_workers=5) as executor:
    certs = executor.map(download_cert, hashes)
for cert in certs:
    if cert is not None:
        print(cert)
print('\nDone', file=stderr)
