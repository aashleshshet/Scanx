import test from 'node:test';
import assert from 'node:assert/strict';
import { assetName } from '../lib/access.mjs';
test('asset requests cannot traverse or select arbitrary files', () => {
 for (const path of [['..','README.md'],['../index.html'],['%2e%2e%2findex.html'],['.env'],['index.html/'],['/index.html']]) assert.equal(assetName(path), null);
 assert.equal(assetName(['demo-vulnerable.json']), 'demo-vulnerable.json');
 assert.equal(assetName([]), 'index.html');
});
