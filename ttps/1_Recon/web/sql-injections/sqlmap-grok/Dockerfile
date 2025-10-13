# syntax=docker/dockerfile:1
# sqlmap-ai: An AI-powered wrapper around SQLMap that makes SQL injection testing more accessible and automated.
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash}

ENV PATH=/sqlmap-ai/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

RUN \
    apk add --no-cache \
        bash \
        curl \
        tzdata \
        coreutils \
        git \
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
    python3 -m venv sqlmap-ai; \
    . sqlmap-ai/bin/activate; \
    python3 -m pip install --upgrade pip; \
    python3 -m pip install --upgrade requests; \
    python3 -m pip install --upgrade python-dotenv; \
    python3 -m pip install --upgrade groq; \
    rm -rf /var/cache/apk/* /root/.cache/*

COPY . .

CMD [ "bash", "-c", "python3 ./run.py --adaptive" ]