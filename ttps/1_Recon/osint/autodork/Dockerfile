FROM python:3.14-rc-slim-bookworm

ENV PATH=/sccmsecrets/bin:/guarddog/bin:/usr/local/bin:/usr/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC

# https://github.com/DataDog/guarddog (comment out below to skip python package scanning)
RUN \
    python3 -m venv guarddog; \
    . guarddog/bin/activate; \
    pip install --upgrade pip guarddog; \
    mkdir /guarddog-results; \
    # scan packagees
    guarddog pypi scan bbrecon --output-format=json >> /guarddog-results/bbrecon.json; \
    guarddog pypi scan tldextract --output-format=json >> /guarddog-results/tldextract.json; \
    # remove guarddog
    pip freeze | xargs pip uninstall -y; \
    pip cache purge

WORKDIR /app

COPY . .

RUN \
    # Attempt to install the packages using pip3
    pip3 install -r requirements.txt 2>&1 | grep "error: externally-managed-environment" >/dev/null; \
    \
    if [ $? -eq 0 ]; then ; \
        # If the pip3 installation failed, install the packages using apt
        echo "Installing required packages using apt"; \
        apt-get update; \
        apt-get install -y $(cat requirements.txt); \
    fi; \
    \
    chmod +x sitedorks.py

CMD ["sh"]