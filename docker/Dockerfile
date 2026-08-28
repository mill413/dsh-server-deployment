ARG DSH_BASE_IMAGE=dsh-server-base:local
FROM ${DSH_BASE_IMAGE}

COPY . /opt/dsh-server-deployment

RUN npm ci --omit=dev --ignore-scripts --prefix /opt/dsh-server-deployment \
    && useradd --system --no-create-home --shell /usr/sbin/nologin dsh-gateway \
    && mkdir -p /usr/local/libexec/dsh \
    && install -o root -g root -m 0755 /opt/dsh-server-deployment/docker/dsh-users /usr/local/libexec/dsh/ \
    && install -o root -g root -m 0755 /opt/dsh-server-deployment/docker/dsh-register /usr/local/libexec/dsh/ \
    && install -o root -g root -m 0755 /opt/dsh-server-deployment/docker/dsh-provider /usr/local/libexec/dsh/ \
    && install -o root -g root -m 0755 /opt/dsh-server-deployment/bin/dsh-batch-register-models.sh /usr/local/libexec/dsh/ \
    && install -o root -g root -m 0755 /opt/dsh-server-deployment/bin/dsh-file-* /usr/local/libexec/dsh/ \
    && install -o root -g root -m 0755 /opt/dsh-server-deployment/bin/dsh-loopback-guard* /usr/local/libexec/dsh/ \
    && install -o root -g root -m 0440 /opt/dsh-server-deployment/docker/dsh-gateway.sudoers /etc/sudoers.d/dsh-gateway \
    && visudo -cf /etc/sudoers.d/dsh-gateway \
    && mkdir -p /srv/dsh/users /var/lib/dsh-gateway \
    && chmod 0711 /srv/dsh/users \
    && chown dsh-gateway:dsh-gateway /var/lib/dsh-gateway \
    && chmod 0700 /var/lib/dsh-gateway

ENV DSH_USERS_DIR=/srv/dsh/users \
    DSH_GATEWAY_STATE_DIR=/var/lib/dsh-gateway \
    DSH_CONTROL_SOCKET=/run/dsh/control.sock \
    DSH_GATEWAY_PORT=3100 \
    DSH_TENANT_PORT_BASE=3101 \
    DSH_ENABLE_REGISTER=0 \
    COOKIE_SECURE=0 \
    PATH="/usr/local/libexec/dsh:${PATH}"

EXPOSE 3100
HEALTHCHECK --interval=10s --timeout=5s --start-period=90s --retries=6 \
  CMD ["node", "/opt/dsh-server-deployment/docker/healthcheck.js"]

ENTRYPOINT ["/usr/bin/tini", "--", "node", "/opt/dsh-server-deployment/docker/entrypoint.js"]
