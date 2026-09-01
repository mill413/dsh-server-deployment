#!/bin/sh
# Configure Debian APT, npm/pnpm, and pip package sources system-wide.
# The image builder passes explicit values; defaults keep the official sources.
set -eu

apt_mirror="${DSH_APT_MIRROR:-http://deb.debian.org/debian}"
npm_registry="${DSH_NPM_REGISTRY:-https://registry.npmjs.org}"
pip_index_url="${DSH_PIP_INDEX_URL:-https://pypi.org/simple}"
pip_trusted_host="${DSH_PIP_TRUSTED_HOST:-}"

validate_url() {
  label="$1"
  value="$2"
  case "$value" in
    http://*|https://*) ;;
    *) echo "$label must be an http(s) URL: $value" >&2; exit 2 ;;
  esac
  if printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    echo "$label contains control characters" >&2
    exit 2
  fi
}

validate_url DSH_APT_MIRROR "$apt_mirror"
validate_url DSH_NPM_REGISTRY "$npm_registry"
validate_url DSH_PIP_INDEX_URL "$pip_index_url"
case "$apt_mirror" in
  *'|'*|*'&'*) echo 'APT mirror URLs contain unsupported sed replacement characters' >&2; exit 2 ;;
esac

# Debian's official Node images use deb822 sources, while older/custom bases
# may still use /etc/apt/sources.list. The deployment intentionally omits the
# separate debian-security repository and uses only the configured main mirror.
if [ -f /etc/apt/sources.list ]; then
  sed -i \
    -e '/debian-security/d' \
    -e '/security\.debian\.org/d' \
    -e "s|https\?://deb.debian.org/debian|$apt_mirror|g" \
    /etc/apt/sources.list
fi
if [ -f /etc/apt/sources.list.d/debian.sources ]; then
  awk 'BEGIN { RS=""; ORS="\n\n" } $0 !~ /debian-security/ && $0 !~ /security\.debian\.org/' \
    /etc/apt/sources.list.d/debian.sources > /etc/apt/sources.list.d/debian.sources.tmp
  mv /etc/apt/sources.list.d/debian.sources.tmp /etc/apt/sources.list.d/debian.sources
  sed -i "s|https\?://deb.debian.org/debian|$apt_mirror|g" /etc/apt/sources.list.d/debian.sources
fi

# NPM_CONFIG_GLOBALCONFIG makes this authoritative for root, dsh-gateway, and
# every dsh-<username> account. Also populate npm's conventional prefix-global
# path for tools that deliberately ignore that environment variable.
printf 'registry=%s\n' "$npm_registry" > /etc/npmrc
chmod 0644 /etc/npmrc
mkdir -p /usr/local/etc
cp /etc/npmrc /usr/local/etc/npmrc
chmod 0644 /usr/local/etc/npmrc

{
  printf '%s\n' '[global]'
  printf 'index-url = %s\n' "$pip_index_url"
  printf '%s\n' 'disable-pip-version-check = true'
  if [ -n "$pip_trusted_host" ]; then
    if printf '%s' "$pip_trusted_host" | LC_ALL=C grep -q '[[:cntrl:]]'; then
      echo 'DSH_PIP_TRUSTED_HOST contains control characters' >&2
      exit 2
    fi
    printf 'trusted-host = %s\n' "$pip_trusted_host"
  fi
} > /etc/pip.conf
chmod 0644 /etc/pip.conf

printf 'package mirrors configured: apt=%s npm=%s pip=%s\n' \
  "$apt_mirror" "$npm_registry" "$pip_index_url"
