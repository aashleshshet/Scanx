import test from 'node:test';
import assert from 'node:assert/strict';
import { verifiedEmail, assetName } from '../lib/access.mjs';
test('only a verified primary email grants access', () => {
 assert.equal(verifiedEmail(null), false);
 const user = { primaryEmailAddressId: 'a', emailAddresses: [{ id: 'a', verification: { status: 'unverified' } }, { id: 'b', verification: { status: 'verified' } }] };
 assert.equal(verifiedEmail(user), false);
 user.emailAddresses[0].verification.status = 'verified';
 assert.equal(verifiedEmail(user), true);
});
test('asset requests cannot traverse or select arbitrary files', () => {
 for (const path of [['..','README.md'],['../index.html'],['%2e%2e%2findex.html'],['.env'],['index.html/'],['/index.html']]) assert.equal(assetName(path), null);
 assert.equal(assetName(['demo-vulnerable.json']), 'demo-vulnerable.json');
 assert.equal(assetName([]), 'index.html');
});
