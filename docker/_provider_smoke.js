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
    { id: 'vision-model', input: ['text', 'image'] },
  ],
});
const yaml = providerSettingsYaml(provider);

assert.strictEqual(provider.model, 'text-model');
assert.match(yaml, /model: "text-model"/);
assert.match(yaml, /id: "text-model"[\s\S]*?input: \[text\]/);
assert.match(yaml, /id: "vision-model"[\s\S]*?input: \[text, image\]/);

const legacy = validateProvider({
  name: 'legacy',
  baseURL: 'https://gateway.example.com/v1',
  models: ['legacy-model'],
});
assert.match(providerSettingsYaml(legacy), /input: \[text\]/);

assert.throws(() => validateProvider({
  name: 'bad',
  baseURL: 'https://gateway.example.com/v1',
  models: [{ id: 'bad-model', input: ['text', 'audio'] }],
}), /input must contain unique text\/image values/);

console.log('provider configuration smoke tests passed');
