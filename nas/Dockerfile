FROM python:3.11-slim

ARG TARGETARCH=amd64

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates gzip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN set -eux; \
    tag=$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+'); \
    echo "mihomo $tag for $TARGETARCH"; \
    for name in "mihomo-linux-${TARGETARCH}-compatible-${tag}" "mihomo-linux-${TARGETARCH}-${tag}"; do \
      if curl -fsSL -o /tmp/m.gz "https://github.com/MetaCubeX/mihomo/releases/download/${tag}/${name}.gz"; then \
        gunzip -f /tmp/m.gz; mv /tmp/m /app/mihomo; break; \
      fi; \
    done; \
    chmod +x /app/mihomo; \
    /app/mihomo -v

COPY filter.py sources.txt run.sh serve.py /app/
RUN chmod +x /app/run.sh && mkdir -p /app/out

ENV OUT_DIR=/app/out
EXPOSE 18080

CMD ["/app/run.sh"]