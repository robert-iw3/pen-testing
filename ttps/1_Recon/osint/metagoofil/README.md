# Metagoofil

## Introduction

metagoofil searches Google for specific types of files being publicly hosted on a web site and optionally downloads them
to your local box.  This is useful for Open Source Intelligence gathering, penetration tests, or determining what files
your organization is leaking to search indexers like Google.  As an example, it uses the Google query below to find all
the `.pdf` files being hosted on `example.com` and optionally downloads a local copy.

```none
site:example.com filetype:pdf
```

This is a maintained fork of the original <https://github.com/laramies/metagoofil> and is currently installed by default
on the Kali Operating System <https://gitlab.com/kalilinux/packages/metagoofil>.  Unlike the original, a design decision
was made to not do metadata analysis and instead defer to other tools like `exiftool`.

```bash
exiftool -r *.doc | egrep -i "Author|Creator|Email|Producer|Template" | sort -u
```

Comments, suggestions, and improvements are always welcome.  Be sure to follow [@opsdisk](https://twitter.com/opsdisk)
on Twitter for the latest updates.

## Usage

```bash
podman build -t metagoofil .

# This will save the files in the host ./data directory.
podman run -it --name metagoofil \
    --cap-add=net_admin \
    --device /dev/net/tun \
    -v $PWD/data:/data \
    -p 9050 -p 9051 \
    metagoofil

# examples
python3 metagoofil.py -d github.com -f -n 10 -r 4 -t pdf -w

proxychains python3 metagoofil.py -d https://github.com -f -t pdf,doc,xls
```
