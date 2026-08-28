'use strict';

const os = require('os');

function clusterEnabled() {
  return process.env.DSH_CLUSTER_MODE === '1';
}

function nodeId() {
  return String(process.env.DSH_NODE_ID || process.env.POD_UID || process.env.HOSTNAME || os.hostname()).trim();
}

function nodeAddress() {
  const configured = String(process.env.DSH_NODE_ADDRESS || process.env.POD_IP || '').trim();
  if (configured) return configured;
  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const address of addresses || []) {
      if (address && address.family === 'IPv4' && !address.internal) return address.address;
    }
  }
  return '127.0.0.1';
}

function positiveIntegerEnv(name, fallback, minimum = 1) {
  const value = Number(process.env[name] || fallback);
  if (!Number.isInteger(value) || value < minimum) throw new Error(`${name} must be an integer >= ${minimum}`);
  return value;
}

module.exports = {
  clusterEnabled,
  nodeAddress,
  nodeId,
  positiveIntegerEnv,
};
