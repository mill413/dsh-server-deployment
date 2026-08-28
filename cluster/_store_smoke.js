'use strict';

const assert = require('assert');
const { ClusterStore } = require('./store.js');

const databaseUrl = process.env.DSH_CLUSTER_TEST_DATABASE_URL;
if (!databaseUrl) {
  console.error('DSH_CLUSTER_TEST_DATABASE_URL is required');
  process.exit(2);
}

async function main() {
  const suffix = `${process.pid}-${Date.now()}`;
  const username = `cluster-smoke-${suffix}`;
  const a = new ClusterStore({ enabled: true, databaseUrl, nodeId: `node-a-${suffix}`, nodeAddress: '10.0.0.1', gatewayPort: 3100, leaseSeconds: 30 });
  const b = new ClusterStore({ enabled: true, databaseUrl, nodeId: `node-b-${suffix}`, nodeAddress: '10.0.0.2', gatewayPort: 3100, leaseSeconds: 30 });
  try {
    await Promise.all([a.init(), b.init()]);
    const first = await a.acquireTenant(username, 3101);
    assert.equal(first.local, true);
    assert.equal(first.nodeId, a.nodeId);

    const contended = await b.acquireTenant(username, 3101);
    assert.equal(contended.local, false);
    assert.equal(contended.nodeId, a.nodeId);
    assert.equal(await a.renewTenant(username, first.generation), true);

    const issued = await a.issueLoginTicket(username, '/workspace', 60);
    const consumed = await b.consumeLoginTicket(issued.ticket);
    assert.equal(consumed.user, username);
    assert.equal(consumed.returnTo, '/workspace');
    assert.equal(await a.consumeLoginTicket(issued.ticket), null);

    const rateSubject = `rate-${suffix}`;
    assert.equal(await a.rateLimitStatus('smoke', rateSubject), 0);
    assert.equal(await a.recordRateLimitFailure('smoke', rateSubject, 2, 60000, 60000), 0);
    assert((await b.recordRateLimitFailure('smoke', rateSubject, 2, 60000, 60000)) > Date.now());
    assert((await a.rateLimitStatus('smoke', rateSubject)) > Date.now());
    await b.clearRateLimit('smoke', rateSubject);
    assert.equal(await a.rateLimitStatus('smoke', rateSubject), 0);

    await a.markUserActive(username, '192.0.2.10', false);
    await b.updatePresence(username, 'test-tab', 'test-nonce', 'open');
    const clusterState = await a.clusterUserState(60000);
    assert.equal(clusterState.activity.get(username).ip, '192.0.2.10');
    assert.equal(clusterState.online.has(username), true);
    await b.clearUserPresence(username);
    assert.equal((await a.clusterUserState(60000)).online.has(username), false);

    await a.releaseTenant(username, first.generation);
    const takeover = await b.acquireTenant(username, 3101);
    assert.equal(takeover.local, true);
    assert.equal(takeover.nodeId, b.nodeId);
    assert(takeover.generation > first.generation);
    assert.equal(await a.renewTenant(username, first.generation), false);
    await b.deleteUserState(username);
    assert.equal(await a.getTenantOwner(username), null);
    assert.equal((await a.clusterUserState(60000)).activity.has(username), false);
    console.log('cluster store smoke tests passed');
  } finally {
    await Promise.allSettled([a.releaseNode(), b.releaseNode()]);
    await Promise.allSettled([a.close(), b.close()]);
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
