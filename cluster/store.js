'use strict';

const crypto = require('crypto');
const { Pool } = require('pg');
const { clusterEnabled, nodeAddress, nodeId, positiveIntegerEnv } = require('./runtime.js');

class ClusterStore {
  constructor(options = {}) {
    this.enabled = options.enabled === undefined ? clusterEnabled() : !!options.enabled;
    this.nodeId = options.nodeId || nodeId();
    this.nodeAddress = options.nodeAddress || nodeAddress();
    this.gatewayPort = Number(options.gatewayPort || process.env.DSH_GATEWAY_PORT || process.env.PORT || 3100);
    this.leaseSeconds = Number(options.leaseSeconds || positiveIntegerEnv('DSH_TENANT_LEASE_SECONDS', 30, 10));
    this.databaseUrl = options.databaseUrl || process.env.DSH_CLUSTER_DATABASE_URL || '';
    this.pool = null;
    this.initialized = null;
    if (this.enabled && !this.databaseUrl) throw new Error('DSH_CLUSTER_DATABASE_URL is required when DSH_CLUSTER_MODE=1');
  }

  async init() {
    if (!this.enabled) return;
    if (this.initialized) return this.initialized;
    this.initialized = (async () => {
      this.pool = new Pool({
        connectionString: this.databaseUrl,
        max: 4,
        connectionTimeoutMillis: 5000,
        query_timeout: 10000,
      });
      const client = await this.pool.connect();
      try {
        await client.query("SELECT pg_advisory_lock(hashtext('dsh-server-deployment-schema-v1'))");
        await client.query(`
        CREATE TABLE IF NOT EXISTS dsh_cluster_nodes (
          node_id text PRIMARY KEY,
          node_address text NOT NULL,
          gateway_port integer NOT NULL,
          draining boolean NOT NULL DEFAULT false,
          last_seen timestamptz NOT NULL DEFAULT now()
        );
        CREATE TABLE IF NOT EXISTS dsh_tenant_leases (
          username text PRIMARY KEY,
          node_id text NOT NULL,
          node_address text NOT NULL,
          gateway_port integer NOT NULL,
          tenant_port integer NOT NULL,
          generation bigint NOT NULL DEFAULT 1,
          lease_until timestamptz NOT NULL,
          updated_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS dsh_tenant_leases_node_idx ON dsh_tenant_leases(node_id);
        CREATE TABLE IF NOT EXISTS dsh_login_tickets (
          ticket_hash text PRIMARY KEY,
          username text NOT NULL,
          return_to text NOT NULL,
          expires_at timestamptz NOT NULL
        );
        CREATE INDEX IF NOT EXISTS dsh_login_tickets_expiry_idx ON dsh_login_tickets(expires_at);
        CREATE TABLE IF NOT EXISTS dsh_rate_limits (
          scope text NOT NULL,
          subject text NOT NULL,
          attempts integer NOT NULL,
          window_started_at timestamptz NOT NULL,
          locked_until timestamptz,
          PRIMARY KEY(scope, subject)
        );
        CREATE TABLE IF NOT EXISTS dsh_user_activity (
          username text PRIMARY KEY,
          last_active_at timestamptz NOT NULL,
          ip text,
          logged_out boolean NOT NULL DEFAULT false
        );
        CREATE TABLE IF NOT EXISTS dsh_browser_presence (
          username text NOT NULL,
          tab_id text NOT NULL,
          session_nonce text,
          last_seen timestamptz NOT NULL,
          PRIMARY KEY(username, tab_id)
        );
        CREATE TABLE IF NOT EXISTS dsh_cluster_revisions (
          name text PRIMARY KEY,
          revision bigint NOT NULL DEFAULT 0,
          updated_at timestamptz NOT NULL DEFAULT now()
        );
      `);
      } finally {
        try { await client.query("SELECT pg_advisory_unlock(hashtext('dsh-server-deployment-schema-v1'))"); } catch (error) {}
        client.release();
      }
      await this.registerNode(false);
    })();
    return this.initialized;
  }

  async registerNode(draining = false) {
    if (!this.enabled) return;
    if (!this.pool) await this.init();
    await this.pool.query(`
      INSERT INTO dsh_cluster_nodes(node_id, node_address, gateway_port, draining, last_seen)
      VALUES ($1, $2, $3, $4, now())
      ON CONFLICT (node_id) DO UPDATE SET
        node_address = EXCLUDED.node_address,
        gateway_port = EXCLUDED.gateway_port,
        draining = EXCLUDED.draining,
        last_seen = now()
    `, [this.nodeId, this.nodeAddress, this.gatewayPort, draining]);
  }

  async health() {
    if (!this.enabled) return { ok: true, cluster: false };
    await this.init();
    await this.pool.query('SELECT 1');
    return { ok: true, cluster: true, nodeId: this.nodeId, nodeAddress: this.nodeAddress };
  }

  ownerFromRow(row) {
    if (!row) return null;
    return {
      username: row.username,
      nodeId: row.node_id,
      nodeAddress: row.node_address,
      gatewayPort: Number(row.gateway_port),
      tenantPort: Number(row.tenant_port),
      generation: Number(row.generation),
      leaseUntil: new Date(row.lease_until).getTime(),
      local: row.node_id === this.nodeId,
    };
  }

  async acquireTenant(username, tenantPort) {
    if (!this.enabled) return {
      username,
      nodeId: this.nodeId,
      nodeAddress: this.nodeAddress,
      gatewayPort: this.gatewayPort,
      tenantPort,
      generation: 1,
      leaseUntil: Number.MAX_SAFE_INTEGER,
      local: true,
    };
    await this.init();
    const result = await this.pool.query(`
      INSERT INTO dsh_tenant_leases(
        username, node_id, node_address, gateway_port, tenant_port, generation, lease_until, updated_at
      ) VALUES ($1, $2, $3, $4, $5, 1, now() + ($6 * interval '1 second'), now())
      ON CONFLICT (username) DO UPDATE SET
        node_id = EXCLUDED.node_id,
        node_address = EXCLUDED.node_address,
        gateway_port = EXCLUDED.gateway_port,
        tenant_port = EXCLUDED.tenant_port,
        generation = CASE
          WHEN dsh_tenant_leases.node_id = EXCLUDED.node_id THEN dsh_tenant_leases.generation
          ELSE dsh_tenant_leases.generation + 1
        END,
        lease_until = EXCLUDED.lease_until,
        updated_at = now()
      WHERE dsh_tenant_leases.lease_until <= now()
         OR dsh_tenant_leases.node_id = EXCLUDED.node_id
      RETURNING *
    `, [username, this.nodeId, this.nodeAddress, this.gatewayPort, tenantPort, this.leaseSeconds]);
    if (result.rows[0]) return this.ownerFromRow(result.rows[0]);
    const current = await this.pool.query('SELECT * FROM dsh_tenant_leases WHERE username = $1', [username]);
    return this.ownerFromRow(current.rows[0]);
  }

  async getTenantOwner(username) {
    if (!this.enabled) return null;
    await this.init();
    const result = await this.pool.query(
      'SELECT * FROM dsh_tenant_leases WHERE username = $1 AND lease_until > now()',
      [username],
    );
    return this.ownerFromRow(result.rows[0]);
  }

  async renewTenant(username, generation) {
    if (!this.enabled) return true;
    await this.init();
    const result = await this.pool.query(`
      UPDATE dsh_tenant_leases
      SET lease_until = now() + ($4 * interval '1 second'), updated_at = now()
      WHERE username = $1 AND node_id = $2 AND generation = $3
      RETURNING username
    `, [username, this.nodeId, generation, this.leaseSeconds]);
    return result.rowCount === 1;
  }

  async releaseTenant(username, generation) {
    if (!this.enabled) return;
    await this.init();
    await this.pool.query(
      `UPDATE dsh_tenant_leases SET lease_until = now(), updated_at = now()
       WHERE username = $1 AND node_id = $2 AND generation = $3`,
      [username, this.nodeId, generation],
    );
  }

  async releaseNode() {
    if (!this.enabled) return;
    await this.init();
    await this.pool.query(
      'UPDATE dsh_tenant_leases SET lease_until = now(), updated_at = now() WHERE node_id = $1',
      [this.nodeId],
    );
    await this.pool.query('DELETE FROM dsh_cluster_nodes WHERE node_id = $1', [this.nodeId]);
  }

  async setDraining(draining) {
    if (!this.enabled) return;
    await this.init();
    await this.registerNode(draining);
  }

  async issueLoginTicket(username, returnTo, ttlSeconds, maximum = 10000) {
    const ticket = crypto.randomBytes(32).toString('base64url');
    if (!this.enabled) return { ticket, stored: false };
    await this.init();
    const hash = crypto.createHash('sha256').update(ticket).digest('base64url');
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT pg_advisory_xact_lock(hashtext('dsh-login-ticket-capacity'))");
      await client.query('DELETE FROM dsh_login_tickets WHERE expires_at <= now()');
      const count = Number((await client.query('SELECT count(*) AS count FROM dsh_login_tickets')).rows[0].count);
      if (count >= maximum) {
        await client.query('ROLLBACK');
        return { ticket: null, stored: false };
      }
      await client.query(`
        INSERT INTO dsh_login_tickets(ticket_hash, username, return_to, expires_at)
        VALUES ($1, $2, $3, now() + ($4 * interval '1 second'))
      `, [hash, username, returnTo, ttlSeconds]);
      await client.query('COMMIT');
      return { ticket, stored: true };
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch (rollbackError) {}
      throw error;
    } finally {
      client.release();
    }
  }

  async consumeLoginTicket(ticket) {
    if (!this.enabled) return null;
    await this.init();
    const hash = crypto.createHash('sha256').update(ticket).digest('base64url');
    const result = await this.pool.query(`
      DELETE FROM dsh_login_tickets
      WHERE ticket_hash = $1 AND expires_at > now()
      RETURNING username, return_to, expires_at
    `, [hash]);
    const row = result.rows[0];
    return row ? { user: row.username, returnTo: row.return_to, expiresAt: new Date(row.expires_at).getTime() } : null;
  }

  async rateLimitStatus(scope, subject) {
    if (!this.enabled) return 0;
    await this.init();
    const result = await this.pool.query(
      `SELECT locked_until FROM dsh_rate_limits
       WHERE scope = $1 AND subject = $2 AND locked_until > now()`,
      [scope, subject],
    );
    return result.rows[0] ? new Date(result.rows[0].locked_until).getTime() : 0;
  }

  async recordRateLimitFailure(scope, subject, maximum, windowMs, lockMs) {
    if (!this.enabled) return 0;
    await this.init();
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))', [scope, subject]);
      const result = await client.query(
        'SELECT *, now() AS database_now FROM dsh_rate_limits WHERE scope = $1 AND subject = $2 FOR UPDATE',
        [scope, subject],
      );
      const now = result.rows[0] ? new Date(result.rows[0].database_now) : new Date((await client.query('SELECT now() AS database_now')).rows[0].database_now);
      const existing = result.rows[0];
      const windowExpired = !existing || now.getTime() - new Date(existing.window_started_at).getTime() > windowMs;
      const attempts = windowExpired ? 1 : Number(existing.attempts) + 1;
      const windowStartedAt = windowExpired ? now : new Date(existing.window_started_at);
      const lockedUntil = attempts >= maximum ? new Date(now.getTime() + lockMs) : (existing && existing.locked_until);
      await client.query(`
        INSERT INTO dsh_rate_limits(scope, subject, attempts, window_started_at, locked_until)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (scope, subject) DO UPDATE SET
          attempts = EXCLUDED.attempts,
          window_started_at = EXCLUDED.window_started_at,
          locked_until = EXCLUDED.locked_until
      `, [scope, subject, attempts, windowStartedAt, lockedUntil || null]);
      await client.query('COMMIT');
      return lockedUntil ? new Date(lockedUntil).getTime() : 0;
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch (rollbackError) {}
      throw error;
    } finally {
      client.release();
    }
  }

  async clearRateLimit(scope, subject) {
    if (!this.enabled) return;
    await this.init();
    await this.pool.query('DELETE FROM dsh_rate_limits WHERE scope = $1 AND subject = $2', [scope, subject]);
  }

  async markUserActive(username, ip, loggedOut = false) {
    if (!this.enabled) return;
    await this.init();
    await this.pool.query(`
      INSERT INTO dsh_user_activity(username, last_active_at, ip, logged_out)
      VALUES ($1, now(), $2, $3)
      ON CONFLICT (username) DO UPDATE SET
        last_active_at = now(), ip = EXCLUDED.ip, logged_out = EXCLUDED.logged_out
    `, [username, ip || null, loggedOut]);
  }

  async updatePresence(username, tabId, sessionNonce, event) {
    if (!this.enabled) return;
    await this.init();
    if (event === 'close') {
      await this.pool.query('DELETE FROM dsh_browser_presence WHERE username = $1 AND tab_id = $2', [username, tabId]);
      return;
    }
    await this.pool.query(`
      INSERT INTO dsh_browser_presence(username, tab_id, session_nonce, last_seen)
      VALUES ($1, $2, $3, now())
      ON CONFLICT (username, tab_id) DO UPDATE SET
        session_nonce = EXCLUDED.session_nonce, last_seen = now()
    `, [username, tabId, sessionNonce || null]);
  }

  async clearUserPresence(username) {
    if (!this.enabled) return;
    await this.init();
    await this.pool.query('DELETE FROM dsh_browser_presence WHERE username = $1', [username]);
  }

  async clusterUserState(presenceTtlMs) {
    if (!this.enabled) return { activity: new Map(), online: new Set() };
    await this.init();
    const [activityResult, presenceResult] = await Promise.all([
      this.pool.query('SELECT username, last_active_at, ip, logged_out FROM dsh_user_activity'),
      this.pool.query(
        `SELECT DISTINCT username FROM dsh_browser_presence
         WHERE last_seen > now() - ($1 * interval '1 millisecond')`,
        [presenceTtlMs],
      ),
    ]);
    return {
      activity: new Map(activityResult.rows.map((row) => [row.username, {
        at: new Date(row.last_active_at).getTime(),
        ip: row.ip,
        loggedOut: row.logged_out === true,
      }])),
      online: new Set(presenceResult.rows.map((row) => row.username)),
    };
  }

  async deleteUserState(username) {
    if (!this.enabled) return;
    await this.init();
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM dsh_tenant_leases WHERE username = $1', [username]);
      await client.query('DELETE FROM dsh_login_tickets WHERE username = $1', [username]);
      await client.query("DELETE FROM dsh_rate_limits WHERE scope = 'login-user' AND subject = $1", [username]);
      await client.query('DELETE FROM dsh_user_activity WHERE username = $1', [username]);
      await client.query('DELETE FROM dsh_browser_presence WHERE username = $1', [username]);
      await client.query('COMMIT');
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch (rollbackError) {}
      throw error;
    } finally {
      client.release();
    }
  }

  async withAdvisoryLock(name, operation) {
    if (!this.enabled) return operation();
    await this.init();
    const client = await this.pool.connect();
    try {
      await client.query('SELECT pg_advisory_lock(hashtext($1))', [`dsh-cluster:${name}`]);
      return await operation();
    } finally {
      try { await client.query('SELECT pg_advisory_unlock(hashtext($1))', [`dsh-cluster:${name}`]); } catch (error) {}
      client.release();
    }
  }

  async getRevision(name) {
    if (!this.enabled) return 0;
    await this.init();
    const result = await this.pool.query('SELECT revision FROM dsh_cluster_revisions WHERE name = $1', [name]);
    return result.rows[0] ? Number(result.rows[0].revision) : 0;
  }

  async bumpRevision(name) {
    if (!this.enabled) return 0;
    await this.init();
    const result = await this.pool.query(`
      INSERT INTO dsh_cluster_revisions(name, revision, updated_at)
      VALUES ($1, 1, now())
      ON CONFLICT (name) DO UPDATE SET
        revision = dsh_cluster_revisions.revision + 1,
        updated_at = now()
      RETURNING revision
    `, [name]);
    return Number(result.rows[0].revision);
  }

  async close() {
    if (this.pool) await this.pool.end();
  }
}

module.exports = { ClusterStore };
