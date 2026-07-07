FROM ghcr.io/home-assistant/amd64-base-python:3.11-alpine3.18

# Install nmap and deps
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    python3 \
    curl

# Copy app files
COPY rootfs /

# Fix permissions
RUN chmod a+x /usr/bin/netscan/run.sh \
    && mkdir -p /data/netscan

WORKDIR /usr/bin/netscan

CMD ["/usr/bin/netscan/run.sh"]
