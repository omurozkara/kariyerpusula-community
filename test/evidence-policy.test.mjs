import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createEvidenceKey, validateEvidenceKey, canAccessEvidence,
  matchesEvidenceSignature, assertLocalTestTarget,
} from '../src/index.mjs';

const id = 'complaint_2';
test('generates unique unpredictable keys without client filenames', () => {
 const a=createEvidenceKey(id, 'image/jpeg'),b=createEvidenceKey(id,'image/jpeg');
 assert.match(a, /^complaint_2\/[0-9a-f]{32}\.jpg$/);
 assert.notEqual(a,b);
 assert.equal(validateEvidenceKey(a), true);
});
test('rejects traversal, empty IDs and hostile MIME',()=>{
 for(const value of ['../etc', '', 'foo/bar','a b','a\\b','💥']) assert.throws(()=>createEvidenceKey(value,'image/png'));
 assert.throws(()=>createEvidenceKey('ok','image/svg+xml'));
});
test('validates paths without accepting public URLs or traversal',()=>{
 for(const value of ['https://example.org/evidence/a.pdf', '../x.png', 'a/../../x.png', 'a/ABC.pdf', 'a/b.pdf',null,42])
  assert.equal(validateEvidenceKey(value), false);
});
test('author can access their own evidence',()=>assert.equal(canAccessEvidence({viewerId:'1',ownerId:'1'}),true));
test('moderator and admin may access (only after trusted identity verification)',()=>{
 for(const role of ['MODERATOR','ADMIN']) assert.equal(canAccessEvidence({viewerId:'2',ownerId:'1',role}),true);
});
test('other users are denied without explicit approval',()=>{
 for(const role of [undefined,'USER','COMPANY','admin']) assert.equal(canAccessEvidence({viewerId:'2',ownerId:'1',role}),false);
});
test('absent identity or owner fails closed',()=>{
 assert.equal(canAccessEvidence({viewerId:'1'}),false);
 assert.equal(canAccessEvidence({ownerId:'1'}),false);
 assert.equal(canAccessEvidence(),false);
});
test('explicit grant must be a boolean true',()=>{
 assert.equal(canAccessEvidence({viewerId:'2',ownerId:'1',explicitGrant:true}),true);
 assert.equal(canAccessEvidence({viewerId:'2',ownerId:'1',explicitGrant:'true'}),false);
});
test('recognizes PNG and rejects mislabeled payloads',()=>{
 const png=Uint8Array.from([137,80,78,71,13,10,26,10,0]);
 assert.equal(matchesEvidenceSignature(png,'image/png'),true);
 assert.equal(matchesEvidenceSignature(png,'image/jpeg'),false);
});
test('recognizes JPEG signatures',()=>assert.equal(matchesEvidenceSignature(Uint8Array.of(255,216,255,0,0),'image/jpeg'),true));
test('recognizes PDF signatures',()=>assert.equal(matchesEvidenceSignature(new TextEncoder().encode('%PDF-1.7'), 'application/pdf'),true));
test('recognizes WEBP RIFF signature',()=>{
 const b=Uint8Array.from([82,73,70,70,9,0,0,0,87,69,66,80,0]);
 assert.equal(matchesEvidenceSignature(b,'image/webp'),true);
});
test('rejects empty, arbitrary and suspicious buffers',()=>{
 assert.equal(matchesEvidenceSignature(Uint8Array.of(0),'image/png'),false);
 assert.equal(matchesEvidenceSignature(new TextEncoder().encode('<svg onload=1>'),'image/png'),false);
 assert.equal(matchesEvidenceSignature(new TextEncoder().encode('%PDF-1.7'),'application/javascript'),false);
});
test('accepts local loopback test target',()=>{
 for(const url of ['http://localhost:3004','http://127.0.0.1:3004','http://[::1]:3004'])
 assert.match(assertLocalTestTarget(url), /^http:/);
});
test('rejects remote or private-network E2E target',()=>{
 for(const url of ['https://localhost','https://production.example','http://production.example','http://192.168.0.2:3000','http://10.0.0.3','http://localhost.evil.com','bad://url','javascript:alert(1)','http://user:pass@localhost:3000'])
  assert.throws(()=>assertLocalTestTarget(url));
});
