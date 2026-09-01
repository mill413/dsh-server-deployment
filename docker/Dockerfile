ARG DSH_BASE_IMAGE=dsh-server-base:local
FROM ${DSH_BASE_IMAGE}

COPY . /opt/dsh-server-deployment

ARG DSH_APT_MIRROR=http://deb.debian.org/debian
ARG DSH_NPM_REGISTRY=https://registry.npmjs.org
ARG DSH_PIP_INDEX_URL=https://pypi.org/simple
ARG DSH_PIP_TRUSTED_HOST=""

# These must be in the environment before any final-stage npm/pnpm command.
# pnpm does not reliably consume npm's prefix-global /usr/local/etc/npmrc when
# DSH runs it with an isolated HOME, so the registry is also explicit here.
ENV DSH_NPM_REGISTRY=${DSH_NPM_REGISTRY} \
    NPM_CONFIG_GLOBALCONFIG=/etc/npmrc \
    NPM_CONFIG_REGISTRY=${DSH_NPM_REGISTRY} \
    npm_config_registry=${DSH_NPM_REGISTRY} \
    PNPM_CONFIG_REGISTRY=${DSH_NPM_REGISTRY} \
    pnpm_config_registry=${DSH_NPM_REGISTRY} \
    PIP_CONFIG_FILE=/etc/pip.conf \
    PIP_INDEX_URL=${DSH_PIP_INDEX_URL} \
    PIP_TRUSTED_HOST=${DSH_PIP_TRUSTED_HOST}

# Configure mirrors again in the final layer so an older compatible base can
# be reused while still giving every runtime user the requested global npm/pip
# configuration. Installing python3-pip here is idempotent for a rebuilt base.
RUN chmod 0755 /opt/dsh-server-deployment/docker/configure-package-mirrors.sh \
    && DSH_APT_MIRROR="$DSH_APT_MIRROR" \
      DSH_NPM_REGISTRY="$DSH_NPM_REGISTRY" \
      DSH_PIP_INDEX_URL="$DSH_PIP_INDEX_URL" \
      DSH_PIP_TRUSTED_HOST="$DSH_PIP_TRUSTED_HOST" \
      /opt/dsh-server-deployment/docker/configure-package-mirrors.sh \
    && apt-get update \
    && apt-get install -y --no-install-recommends python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Keep deployment-specific plugins in the final image so the expensive DSH
# base can be reused unchanged. The argument is a JSON array of npm/Git/file
# specs, for example ["@scope/plugin@1.2.3","https://example/plugin.git"].
# /opt/dsh-public is image-owned and is not hidden by the runtime PVC.
ARG DSH_FINAL_WEB_PLUGINS_JSON="[]"
RUN DSH_FINAL_WEB_PLUGINS_JSON="${DSH_FINAL_WEB_PLUGINS_JSON}" \
      node /opt/dsh-server-deployment/docker/install-final-plugins.js \
    && chown -R root:root /opt/dsh-public \
    && chmod -R a+rX,go-w /opt/dsh-public

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
