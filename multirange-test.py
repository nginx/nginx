import requests
import re
import random
import signal
import subprocess

quit_received = False
two_o_sixes = 0
two_o_os = 0

def signal_handler(sig, frame):
    global quit_received
    print("206/200: ", two_o_sixes, two_o_os)
    quit_received = True

signal.signal(signal.SIGINT, signal_handler)

ORIGIN='http://127.0.0.1:8080/'
CACHE='http://sliced/'
uri = 'f2p24b'
origin_file_size = 16777216
#max_distance = origin_file_size//25
max_distance = 10000

range_start = 'bytes='


c = 0
comp = True

while (comp and not quit_received):
    range_header = range_start
    rangecount = random.randint(2,12)

    for i in (range(rangecount)):
        a = random.randint(1, origin_file_size - max_distance)
        b = a + random.randint(0, max_distance)

        #open ranges
        # x-      (x ... last)
        # -x (last-x ... last)
        items = ['a', 'b', 'c']
        weights = [0.1, 0.1, 0.8]
        choice = random.choices(items, weights=weights, k=1)[0]
        if choice == 'a':
            a = ""
        elif choice == 'b':
            b = ""
        elif choice == 'c':
            c = ""


        range_header += f'{a}-{b}'
        if ((i+1) < rangecount):
            range_header += ','



    rheader = { 'Range' : range_header }

    origin_response = requests.get(f"{ORIGIN}{uri}", headers=rheader)
    origin_response_headers = origin_response.headers
    if ('boundary=' in origin_response_headers['content-type']):
        origin_boundary_pattern = origin_response_headers['content-type'].split("boundary=")[1]
        stripped_origin_response = re.sub(origin_boundary_pattern.encode(), b'BOUNDARY', origin_response.content.replace(b'\r\n', b''))


    cache_response = requests.get(f"{CACHE}{uri}", headers=rheader)
    cache_response_headers = cache_response.headers
    if ('boundary=' in cache_response_headers['content-type']):
        cache_boundary_pattern = cache_response_headers['content-type'].split("boundary=")[1]
        stripped_cache_response = re.sub(cache_boundary_pattern.encode(), b'BOUNDARY', cache_response.content.replace(b'\r\n', b''))


    if(cache_response.status_code == 206 == origin_response.status_code):
        two_o_sixes += 1
        comp =  stripped_cache_response == stripped_origin_response
    elif (cache_response.status_code == 200 == origin_response.status_code):
        two_o_os += 1
        comp =  cache_response.content == origin_response.content
    else:
        print(cache_response.status_code, origin_response.status_code, range_header)
        quit()


    print('(', origin_response.status_code, rangecount, '),', end='', flush=True)

    if not (comp):
        print(range_header)
        with open('/tmp/origin.txt', 'wb') as originc:
            originc.write(stripped_origin_response)
        with open('/tmp/cache.txt', 'wb') as cachec:
            cachec.write(stripped_cache_response)
        quit()


    if (random.choice([True, False])):
        subprocess.run('find /mnt/disk*/cache/ -type f -delete', shell=True, check=True)
