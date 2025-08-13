import pefile
import sys
import os
import re
from Crypto.Cipher import AES


if __name__ == "__main__":

    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    pe = pefile.PE(sys.argv[1], fast_load=True)
    pe.parse_data_directories(directories=d)

    rt_rcdata_idx = [
        entry.id for entry in
        pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])

    rt_rcdata_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_rcdata_idx]
    for e in rt_rcdata_directory.directory.entries:
        offset = e.directory.entries[0].data.struct.OffsetToData
        size = e.directory.entries[0].data.struct.Size
        data = pe.get_data(offset, size)
        print(f'res {e.name} at 0x{offset:x} len 0x{size:x}')
        open(f'{e.name}.res.bin', 'wb').write(data)
