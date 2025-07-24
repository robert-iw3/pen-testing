# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="docker:rc-dind" \
    image_hash="2dd54cd126e302ef9fc865c080e57cf13efbc0b5bc0fb95805d0d1639952ad08"
    
FROM ${repo}/${base_image}@sha256:${image_hash}

ENV project_name=test \
    web_port=8080 \
    neo4j_port=10501 \
    bolt_port=10001

ENV PATH=/bloodhound/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC 

RUN \
    apk add --no-cache \
        bash \
        tzdata \
        coreutils \
        findutils \
        ca-certificates \
        libgcc \
        libstdc++ \
        iputils \
        openssl \
        musl-dev \
        linux-headers \
        python3 \
        py3-pip

COPY . .

RUN \
    python3 -m venv bloodhound; \
    . bloodhound/bin/activate; \
    pip install --upgrade pip; \
    pip install -r requirements.txt; \
    rm -rf /var/cache/apk/* /root/.cache/*

CMD [ "bash", "-c", "python3 bloodhound-automation.py start -bp ${bolt_port} -np ${neo4j_port} -wp ${web_port} ${project_name}" ]