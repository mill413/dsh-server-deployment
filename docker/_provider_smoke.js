#!/usr/bin/env node
'use strict';

const assert = require('assert');
const { providerSettingsYaml, validateProvider } = require('./entrypoint.js');

const provider = validateProvider({
  name: 'vision-gateway',
  baseURL: 'https://gateway.example.com/v1',
  api: 'openai-completions',
  models: [
    { id: 'text-model', input: ['text'] },
    { id: 'vision-model', input: ['text', 'image'], contextWindow: 131072, maxTokens: 16384 },
  ],
});
const yaml = providerSettingsYaml(provider);

assert.strictEqual(provider.model, 'text-model');
assert.match(yaml, /model: "text-model"/);
assert.match(yaml, /id: "text-model"[\s\S]*?input: \[text\]/);
assert.match(yaml, /id: "vision-model"[\s\S]*?input: \[text, image\]/);
assert.match(yaml, /id: "text-model"[\s\S]*?contextWindow: 32768[\s\S]*?maxTokens: 8192/);
assert.match(yaml, /id: "vision-model"[\s\S]*?contextWindow: 131072[\s\S]*?maxTokens: 16384/);

const legacy = validateProvider({
  name: 'legacy',
  baseURL: 'https://gateway.example.com/v1',
  models: ['legacy-model'],
});
assert.match(providerSettingsYaml(legacy), /input: \[text\]/);

const snakeCase = validateProvider({
  name: 'snake-case',
  baseURL: 'https://gateway.example.com/v1',
  models: [{ id: 'large-model', context_window: 262144, max_tokens: 32768 }],
});
assert.strictEqual(snakeCase.models[0].contextWindow, 262144);
assert.strictEqual(snakeCase.models[0].maxTokens, 32768);

assert.throws(() => validateProvider({
  name: 'bad',
  baseURL: 'https://gateway.example.com/v1',
  models: [{ id: 'bad-model', input: ['text', 'audio'] }],
}), /input must contain unique text\/image values/);

assert.throws(() => validateProvider({
  name: 'bad-limits',
  baseURL: 'https://gateway.example.com/v1',
  models: [{ id: 'bad-model', contextWindow: 4096, maxTokens: 8192 }],
}), /maxTokens must not exceed contextWindow/);

console.log('provider configuration smoke tests passed');
