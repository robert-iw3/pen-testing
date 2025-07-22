# syntax=docker/dockerfile:1
# HTML Injection: Automates HTML injection, HTTP Parameter Pollution, and XXE attacks.
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="08001109a7d679fe33b04fa51d681bd40b975d8f5cea8c3ef6c0eccb6a7338ce"
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ARG url

ENV PATH=/htmlinject/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC \
    URL=$url

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
    python3 -m venv htmlinject; \
    . htmlinject/bin/activate; \
    python3 -m pip install --upgrade pip; \
    python3 -m pip install --upgrade requests; \
    python3 -m pip install --upgrade beautifulsoup4; \
    python3 -m pip install --upgrade tqdm; \
    python3 -m pip install --upgrade tabulate; \
    rm -rf /var/cache/apk/* /root/.cache/*

COPY . .    

CMD [ "bash", "-c", "python3 ./html_injection.py -u ${URL} --hpp --htmli --xxe" ]
# podman build -t htmli --build-arg url=https://someurl.url .
# podman run htmli