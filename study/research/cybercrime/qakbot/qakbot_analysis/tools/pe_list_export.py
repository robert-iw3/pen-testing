import pefile
import sys, os

if __name__ == "__main__":
    for fn in sys.argv[1:]:
        dllname = os.path.basename(fn)
        d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        pe = pefile.PE(fn, fast_load=True)
        pe.parse_data_directories(directories=d)
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if e.name: print(f'{dllname}::{e.name.decode()}')