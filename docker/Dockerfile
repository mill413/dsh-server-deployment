FROM node:24-bookworm AS harness-build

ARG DSH_REPOSITORY=https://github.com/deepseek-ai/deepseek-harness.git
ARG DSH_REF=master

RUN corepack enable \
    && corepack prepare pnpm@11.7.0 --activate \
    && apt-get update \
    && apt-get install -y --no-install-recommends git python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/deepseek-harness
RUN git clone --depth 1 --branch "$DSH_REF" "$DSH_REPOSITORY" . \
    && git rev-parse HEAD > .dsh-source-commit
RUN pnpm install --frozen-lockfile \
    && pnpm run build

FROM node:24-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates curl iptables openssl sudo tini util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin dsh-gateway

COPY --from=harness-build /build/deepseek-harness /opt/deepseek-harness
COPY . /opt/dsh-server-deployment

RUN mkdir -p /usr/local/libexec/dsh \
    && install -o root -g root -m 0755 /opt/dsh-server-deployment/docker/dsh-users /usr/local/libexec/dsh/ \
    && install -o root -g root -m 0755 /opt/dsh-server-deployment/docker/dsh-register /usr/local/libexec/dsh/ \
    && install -o root -g root -m 0755 /opt/dsh-server-deployment/docker/dsh-provider /usr/local/libexec/dsh/ \
    && install -o root -g root -m 0755 /opt/dsh-server-deployment/bin/dsh-file-* /usr/local/libexec/dsh/ \
    && install -o root -g root -m 0755 /opt/dsh-server-deployment/bin/dsh-loopback-guard* /usr/local/libexec/dsh/ \
    && install -o root -g root -m 0440 /opt/dsh-server-deployment/docker/dsh-gateway.sudoers /etc/sudoers.d/dsh-gateway \
    && visudo -cf /etc/sudoers.d/dsh-gateway \
    && mkdir -p /srv/dsh/users /var/lib/dsh-gateway \
    && chmod 0711 /srv/dsh/users \
    && chown dsh-gateway:dsh-gateway /var/lib/dsh-gateway \
    && chmod 0700 /var/lib/dsh-gateway

ENV DSH_APP_DIR=/opt/deepseek-harness \
    DSH_USERS_DIR=/srv/dsh/users \
    DSH_GATEWAY_STATE_DIR=/var/lib/dsh-gateway \
    DSH_GATEWAY_PORT=3100 \
    DSH_TENANT_PORT_BASE=3101 \
    COOKIE_SECURE=0 \
    PATH="/usr/local/libexec/dsh:${PATH}"

EXPOSE 3100
HEALTHCHECK --interval=10s --timeout=5s --start-period=90s --retries=6 \
  CMD ["node", "/opt/dsh-server-deployment/docker/healthcheck.js"]

ENTRYPOINT ["/usr/bin/tini", "--", "node", "/opt/dsh-server-deployment/docker/entrypoint.js"]
