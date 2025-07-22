# Usage
This section provides step-by-step instructions on how to use the provided Python scripts to generate MP4 files and then create a modified version that simulates the vulnerability CVE-2022-41741.

# Generating a Standard MP4 File
Prepare your environment
`pip install -r requirements.txt`
# Run the script:
Use the mp4.py script to create a standard MP4 file. This script generates a simple MP4 video with predefined content.
The script will output a file named output.mp4 in the current directory.
`python mp4.py`
# Creating an "Evil" MP4 Version
Prepare for creating the modified file:
Ensure all prerequisites are still satisfied, as the second script may rely on similar libraries or settings.
Run the evilmp4.py script:
This script takes the output.mp4 created by the previous script and modifies it to simulate the CVE-2022-41741 vulnerability.
The script will output a file named evil_output.mp4, which is the "evil" version of the original MP4. This file is crafted to demonstrate how the CVE-2022-41741 vulnerability could potentially be exploited.
`python evilmp4.py`

# All together
```
git clone https://github.com/dumbbutt0/evilMP4.git
pip install -r requirements.txt
python mp4.py
python evilmp4.py
```
