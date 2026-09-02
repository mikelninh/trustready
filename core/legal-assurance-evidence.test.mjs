import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import {publicKeyFingerprint,signEnvelope} from './legal-key-identity.mjs'
import {verifiedClaim,verifyAssuranceEnvelope} from './legal-assurance-evidence.mjs'

const NOW=new Date('2026-09-02T16:00:00Z')
const liveKey=crypto.generateKeyPairSync('ed25519')
const attacker=crypto.generateKeyPairSync('ed25519')
const fingerprint=publicKeyFingerprint(liveKey.publicKey)
function claim(level='E3'){return{verified:true,evidence_level:level,evidence_hash:`sha256:${'a'.repeat(64)}`,observed_at:'2026-09-02T15:55:00Z',expires_at:'2026-09-02T17:00:00Z'}}
function envelope({key=liveKey,body={},purpose='live_qualification'}={}){return signEnvelope({body:{schema:purpose==='live_qualification'?'trustready-live-assurance-v1':'trustready-independent-assurance-v1',deployment_id:'bao-shadow',generated_at:'2026-09-02T15:55:00Z',expires_at:purpose==='live_qualification'?'2026-09-03T15:55:00Z':'2026-10-02T15:55:00Z',claims:{hsm:claim(),...body.claims},...body},private_key:key.privateKey,key_id:'external-auditor-1',purpose})}

test('pinned external trust anchor verifies signed live assurance',()=>{const v=verifyAssuranceEnvelope({envelope:envelope(),trusted_public_key:liveKey.publicKey,expected_fingerprint:fingerprint,purpose:'live_qualification',now:NOW});assert.equal(v.valid,true);assert.equal(verifiedClaim(v,'hsm',{levels:['E3'],now:NOW}),true)})
test('self-authored booleans and unsigned JSON cannot become audit evidence',()=>{const v=verifyAssuranceEnvelope({envelope:{hsm:{verified:true}},trusted_public_key:liveKey.publicKey,expected_fingerprint:fingerprint,purpose:'live_qualification',now:NOW});assert.equal(v.valid,false)})
test('attacker signature fails against pinned auditor key',()=>{const v=verifyAssuranceEnvelope({envelope:envelope({key:attacker}),trusted_public_key:liveKey.publicKey,expected_fingerprint:fingerprint,purpose:'live_qualification',now:NOW});assert.equal(v.valid,false)})
test('fingerprint mismatch fails before evidence evaluation',()=>{const v=verifyAssuranceEnvelope({envelope:envelope(),trusted_public_key:liveKey.publicKey,expected_fingerprint:`sha256:${'0'.repeat(64)}`,purpose:'live_qualification',now:NOW});assert.equal(v.valid,false)})
test('claim needs evidence hash, level and fresh timestamps',()=>{for(const bad of[{verified:true,evidence_level:'E3',observed_at:'2026-09-02T15:55:00Z',expires_at:'2026-09-02T17:00:00Z'},{...claim(),evidence_level:'E1'},{...claim(),expires_at:'2026-09-02T15:59:00Z'}]){const v=verifyAssuranceEnvelope({envelope:envelope({body:{claims:{hsm:bad}}}),trusted_public_key:liveKey.publicKey,expected_fingerprint:fingerprint,purpose:'live_qualification',now:NOW});assert.equal(v.valid,true);assert.equal(verifiedClaim(v,'hsm',{levels:['E3'],now:NOW}),false)}})
test('independent assurance uses separate purpose and requires E4 claims',()=>{const env=envelope({purpose:'independent_assurance',body:{claims:{independent_pentest:claim('E4')}}});const v=verifyAssuranceEnvelope({envelope:env,trusted_public_key:liveKey.publicKey,expected_fingerprint:fingerprint,purpose:'independent_assurance',now:NOW});assert.equal(v.valid,true);assert.equal(verifiedClaim(v,'independent_pentest',{levels:['E4'],now:NOW}),true);assert.equal(verifiedClaim(v,'independent_pentest',{levels:['E3'],now:NOW}),false)})
