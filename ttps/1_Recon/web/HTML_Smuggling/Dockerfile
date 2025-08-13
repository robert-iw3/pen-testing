# syntax=docker/dockerfile:1
# HTML Smuggling: Hide malware payloads via an encoded script in a specially crafted HTML attachment or web page.
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ARG filename
ARG filepath

ENV PATH=/htmlsmuggle/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC \
    FILENAME=$filename \
    FILEPATH=$filepath

RUN \
    apk add --no-cache \
        bash \
        curl \
        tzdata \
        coreutils \
        grep \
        ca-certificates \
        libgcc \
        libstdc++ \
        libxml2 \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip; \
    \
    python3 -m venv htmlsmuggle; \
    . htmlsmuggle/bin/activate; \
    python3 -m pip install --upgrade pip; \
    python3 -m pip install --upgrade requests; \
    python3 -m pip install --upgrade beautifulsoup4; \
    python3 -m pip install --upgrade tqdm; \
    python3 -m pip install --upgrade tabulate; \
    python3 -m pip install --upgrade pyinstaller; \
    rm -rf /var/cache/apk/* /root/.cache/*

COPY . .

CMD [ "bash", "-c", "python3 ./HtmlSmuggling.py ${FILENAME} ${FILEPATH}" ]
# podman build -t htmlsmuggle --build-arg filename=important_notes.txt --build-arg filepath=c:\Users\Neo\Desktop\important_notes.txt .
# podman run htmlsmuggle