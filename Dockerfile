FROM python:3.12-alpine3.20 AS builder

COPY pyproject.toml /tmp/
COPY certbot_dns_forpsi/ /tmp/certbot_dns_forpsi/

WORKDIR /tmp
RUN pip install --no-cache-dir --target /app .

FROM certbot/certbot:latest AS runtime

LABEL maintainer="public.repo.uncover565@passmail.net"
LABEL description="Certbot with DNS-Forpsi plugin for automated SSL certificate management"
LABEL version="0.1.0"
LABEL org.opencontainers.image.source="https://github.com/roshek/certbot-dns-forpsi"
LABEL org.opencontainers.image.documentation="https://github.com/roshek/certbot-dns-forpsi#README.md"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /app /usr/local/lib/python3.12/site-packages/

RUN pip install --no-cache-dir --upgrade pip
