#!/bin/sh
set -eu

repo_dir=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
compose_file="$repo_dir/docker/compose.cluster.yml"
project="dsh-cluster-smoke-$$"
data_dir=$(mktemp -d /tmp/dsh-cluster-data.XXXXXX)
cookie_jar=$(mktemp /tmp/dsh-cluster-cookie.XXXXXX)
login_html=$(mktemp /tmp/dsh-cluster-login.XXXXXX)
ticket_jar=$(mktemp /tmp/dsh-cluster-ticket.XXXXXX)
registered_jar=$(mktemp /tmp/dsh-cluster-registered.XXXXXX)
test_port=$(node -e 'const n=require("net");const s=n.createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close();});')

export DSH_CLUSTER_DATA_DIR="$data_dir"
export DSH_GATEWAY_HOST_PORT="$test_port"

cleanup() {
  docker compose -p "$project" -f "$compose_file" down -v --remove-orphans >/dev/null 2>&1 || true
  docker run --rm -v "$data_dir:/target" busybox:latest sh -c 'rm -rf /target/* /target/.[!.]* /target/..?*' >/dev/null 2>&1 || true
  rmdir "$data_dir" >/dev/null 2>&1 || true
  rm -f "$cookie_jar" "$login_html" "$ticket_jar" "$registered_jar"
}
on_signal() {
  trap - EXIT INT TERM
  cleanup
  exit 130
}
trap cleanup EXIT
trap on_signal INT TERM

cd "$repo_dir"
docker compose -p "$project" -f "$compose_file" up -d --build --scale dsh-multitenant=3

i=0
until curl -fsS "http://127.0.0.1:$test_port/__gw/health" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 90 ]; then
    docker compose -p "$project" -f "$compose_file" logs --tail=200
    echo "cluster gateway did not become ready" >&2
    exit 1
  fi
  sleep 2
done

nodes=''
node_count=0
for i in $(seq 1 60); do
  node=$(curl -fsS "http://127.0.0.1:$test_port/__gw/health" \
    | node -e 'let b="";process.stdin.on("data",c=>b+=c).on("end",()=>console.log(JSON.parse(b).nodeId));')
  nodes="$nodes\n$node"
  node_count=$(printf '%b\n' "$nodes" | sed '/^$/d' | sort -u | wc -l)
  [ "$node_count" -eq 3 ] && break
  sleep 1
done
[ "$node_count" -eq 3 ] || { echo "expected 3 load-balanced nodes, got $node_count" >&2; exit 1; }

curl -fsS -c "$cookie_jar" "http://127.0.0.1:$test_port/login" -o "$login_html"
csrf=$(awk '$6 == "dsh_csrf" {print $7}' "$cookie_jar" | tail -1)
login_code=$(curl -sS -b "$cookie_jar" -c "$cookie_jar" -o /dev/null -w '%{http_code}' \
  -X POST "http://127.0.0.1:$test_port/login" \
  --data-urlencode "csrf=$csrf" \
  --data-urlencode 'username=alice' \
  --data-urlencode 'password=alice-test-password')
if [ "$login_code" != 302 ]; then
  echo "alice login failed: HTTP $login_code" >&2
  docker compose -p "$project" -f "$compose_file" logs --tail=160 dsh-multitenant >&2
  exit 1
fi

for i in 1 2 3 4 5 6 7 8 9; do
  code=$(curl -sS -b "$cookie_jar" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$test_port/")
  [ "$code" = 200 ] || { echo "proxied session request failed: HTTP $code" >&2; exit 1; }
done

ticket_json=$(curl -fsS -X POST "http://127.0.0.1:$test_port/api/login-ticket" \
  -H 'Authorization: Bearer login-test-token' -H 'Content-Type: application/json' \
  -d '{"username":"bob","returnTo":"/"}')
login_url=$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).loginUrl)' "$ticket_json")
ticket_code=$(curl -sS -c "$ticket_jar" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$test_port$login_url")
[ "$ticket_code" = 302 ] || { echo "cross-node ticket login failed: HTTP $ticket_code" >&2; exit 1; }

plugin_worker=$(docker compose -p "$project" -f "$compose_file" ps -q dsh-multitenant | head -1)
docker exec "$plugin_worker" dsh-users plugin add \
  file:/opt/dsh-server-deployment/test-fixtures/cluster-test-plugin \
  --name dsh-cluster-test-plugin >/dev/null
i=0
while true; do
  plugin_nodes=0
  for container in $(docker compose -p "$project" -f "$compose_file" ps -q dsh-multitenant); do
    if docker exec "$container" dsh-users plugin list | grep -q '^dsh-cluster-test-plugin'; then
      plugin_nodes=$((plugin_nodes + 1))
    fi
  done
  [ "$plugin_nodes" -eq 3 ] && break
  i=$((i + 1))
  [ "$i" -lt 30 ] || { echo "plugin revision reached only $plugin_nodes replica(s)" >&2; exit 1; }
  sleep 2
done
plugin_profiles=$(docker exec "$plugin_worker" node -e '
  const fs=require("fs"),path=require("path");
  const db=JSON.parse(fs.readFileSync("/var/lib/dsh/gateway/users.json","utf8"));
  let count=0;
  for(const user of Object.values(db.users)){
    const manifest=JSON.parse(fs.readFileSync(path.join(user.home,"profiles/web/package.json"),"utf8"));
    if(manifest.dsh?.profile?.bundles?.includes("dsh-cluster-test-plugin"))count++;
  }
  process.stdout.write(String(count));')
[ "$plugin_profiles" -eq 3 ] || { echo "plugin was synchronized to $plugin_profiles/3 profiles" >&2; exit 1; }

successes=$(seq 1 6 | xargs -P 6 -I{} sh -c \
  "curl --max-time 180 -sS -o /dev/null -w '%{http_code}\\n' -X POST http://127.0.0.1:$test_port/api/register -H 'Authorization: Bearer register-test-token' -H 'Content-Type: application/json' -d '{\"username\":\"clusteruser\",\"password\":\"cluster-user-password\"}'" \
  | awk '$1 == 200 {count++} END {print count + 0}')
[ "$successes" -eq 1 ] || { echo "expected one successful concurrent registration, got $successes" >&2; exit 1; }

curl -fsS -c "$registered_jar" "http://127.0.0.1:$test_port/login" -o "$login_html"
csrf=$(awk '$6 == "dsh_csrf" {print $7}' "$registered_jar" | tail -1)
registered_login_code=$(curl --max-time 180 -sS -b "$registered_jar" -c "$registered_jar" -o /dev/null -w '%{http_code}' \
  -X POST "http://127.0.0.1:$test_port/login" \
  --data-urlencode "csrf=$csrf" \
  --data-urlencode 'username=clusteruser' \
  --data-urlencode 'password=cluster-user-password')
[ "$registered_login_code" = 302 ] || { echo "new cluster user was not immediately visible: HTTP $registered_login_code" >&2; exit 1; }

owner=$(docker compose -p "$project" -f "$compose_file" exec -T postgres \
  psql -U dsh -d dsh -Atc "select node_id from dsh_tenant_leases where username='alice' and lease_until > now()")
[ -n "$owner" ] || { echo 'alice has no active owner' >&2; exit 1; }
alice_processes=0
for container in $(docker compose -p "$project" -f "$compose_file" ps -q dsh-multitenant); do
  count=$(docker top "$container" -eo user,pid,args | grep -c '[d]sh-alice' || true)
  alice_processes=$((alice_processes + count))
done
[ "$alice_processes" -eq 1 ] || { echo "expected one alice process, got $alice_processes" >&2; exit 1; }
owner_container=''
for container in $(docker compose -p "$project" -f "$compose_file" ps -q dsh-multitenant); do
  hostname=$(docker inspect -f '{{.Config.Hostname}}' "$container")
  if [ "$hostname" = "$owner" ]; then owner_container=$container; break; fi
done
[ -n "$owner_container" ] || { echo "cannot find owner container $owner" >&2; exit 1; }
docker stop "$owner_container" >/dev/null

i=0
until [ "$(curl --max-time 10 -sS -b "$cookie_jar" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$test_port/" || true)" = 200 ]; do
  i=$((i + 1))
  [ "$i" -lt 20 ] || { echo 'tenant takeover timed out' >&2; exit 1; }
  sleep 2
done
generation=$(docker compose -p "$project" -f "$compose_file" exec -T postgres \
  psql -U dsh -d dsh -Atc "select generation from dsh_tenant_leases where username='alice' and lease_until > now()")
[ "$generation" -ge 2 ] || { echo "tenant generation did not advance: $generation" >&2; exit 1; }
alice_processes=0
for container in $(docker compose -p "$project" -f "$compose_file" ps -q dsh-multitenant); do
  count=$(docker top "$container" -eo user,pid,args | grep -c '[d]sh-alice' || true)
  alice_processes=$((alice_processes + count))
done
[ "$alice_processes" -eq 1 ] || { echo "expected one alice process after takeover, got $alice_processes" >&2; exit 1; }

echo 'cluster compose smoke tests passed'
