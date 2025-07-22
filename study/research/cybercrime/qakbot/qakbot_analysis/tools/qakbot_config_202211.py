import sys
import hashlib
from Crypto.Cipher import ARC4
import pefile
import logging
import io
import struct
import socket

logging.basicConfig(level=logging.INFO)

def qbot4_decode_ips(fp):
    hosts = []
    while True:
        data = fp.read(7)
        if not data: break
        flag, ip_dword, port = struct.unpack('>BIH', data)
        if ip_dword == 0: break
        ip = socket.inet_ntoa(struct.pack(">I", ip_dword))
        hosts.append( f'{ip:s}:{port:d}')
    return hosts

if __name__ == "__main__":
    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    pe = pefile.PE(sys.argv[1], fast_load=True)
    pe.parse_data_directories(directories=d)

    rt_rcdata_idx = [ 
        entry.id for entry in
        pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])

    rt_rcdata_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_rcdata_idx]
    i = 0
    for e in rt_rcdata_directory.directory.entries:
        offset = e.directory.entries[0].data.struct.OffsetToData
        size = e.directory.entries[0].data.struct.Size
        data = pe.get_data(offset, size)

        logging.info(f'res {e.name} at 0x{offset:x} len 0x{size:x}')

        key = hashlib.sha1(b'Muhcu#YgcdXubYBu2@2ub4fbUhuiNhyVtcd').digest()
        cipher = ARC4.new(key)
        data_ = cipher.decrypt(data)
        if hashlib.sha1(data_[20:]).digest() != data_[:20]:
            logging.error('failed to decode')
            continue

        data_ = data_[20:]

        key = data_[:20] 
        cipher = ARC4.new(key)
        data_ = cipher.decrypt(data_[20:])
        if hashlib.sha1(data_[20:]).digest() != data_[:20]:
            logging.error('failed to decode stage2')
            continue
        data_ = data_[20:]

        if i == 1: # text
            sys.stdout.buffer.write(data_)
        elif i == 0: # ips
            print('\n'.join(qbot4_decode_ips(io.BytesIO(data_))))
        i += 1

