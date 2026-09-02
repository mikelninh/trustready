import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import {publicKeyFingerprint,signEnvelope} from './legal-key-identity.mjs'
import {trustAnchorsDistinct,verifiedClaim,verifyAssuranceEnvelope} from './legal-assurance-evidence.mjs'

const NOW=new Date('2026-09-02T16:00:00Z')
const liveKey=crypto.generateKeyPairSync('ed25519')
const legalKey=crypto.generateKeyPairSync('ed25519')
const independentKey=crypto.generateKeyPairSync('ed25519')
const attacker=crypto.generateKeyPairSync('ed25519')
const fingerprints={live:publicKeyFingerprint(liveKey.publicKey),legal:publicKeyFingerprint(legalKey.publicKey),independent:publicKeyFingerprint(independentKey.publicKey)}
const schemas={live_qualification:'trustready-live-assurance-v1',legal_privacy_assurance:'trustready-legal-privacy-assurance-v1',independent_assurance:'trustready-independent-assurance-v1'}
function claim(level='E3'){return{verified:true,evidence_level:level,evidence_hash:`sha256:${'a'.repeat(64)}`,observed_at:'2026-09-02T15:55:00Z',expires_at:'2026-09-02T17:00:00Z'}}
function envelope({key=liveKey,body={},purpose='live_qualification'}={}){return signEnvelope({body:{schema:schemas[purpose],deployment_id:'bao-shadow',generated_at:'2026-09-02T15:55:00Z',expires_at:purpose==='live_qualification'?'2026-09-03T15:55:00Z':'2026-10-02T15:55:00Z',claims:{hsm:claim(),...body.claims},...body},private_key:key.privateKey,key_id:`${purpose}-signer-1`,purpose})}
function verify(env,key,fingerprint,purpose){return verifyAssuranceEnvelope({envelope:env,trusted_public_key:key.publicKey,expected_fingerprint:fingerprint,purpose,now:NOW})}

test('pinned external trust anchor verifies signed live assurance',()=>{const v=verify(envelope(),liveKey,fingerprints.live,'live_qualification');assert.equal(v.valid,true);assert.equal(verifiedClaim(v,'hsm',{levels:['E3'],now:NOW}),true)})
test('self-authored booleans and unsigned JSON cannot become audit evidence',()=>{const v=verifyAssuranceEnvelope({envelope:{hsm:{verified:true}},trusted_public_key:liveKey.publicKey,expected_fingerprint:fingerprints.live,purpose:'live_qualification',now:NOW});assert.equal(v.valid,false)})
test('attacker signature fails against pinned auditor key',()=>{const v=verify(envelope({key:attacker}),liveKey,fingerprints.live,'live_qualification');assert.equal(v.valid,false)})
test('fingerprint mismatch fails before evidence evaluation',()=>{const v=verifyAssuranceEnvelope({envelope:envelope(),trusted_public_key:liveKey.publicKey,expected_fingerprint:`sha256:${'0'.repeat(64)}`,purpose:'live_qualification',now:NOW});assert.equal(v.valid,false)})
test('claim needs evidence hash, level and fresh timestamps',()=>{for(const bad of[{verified:true,evidence_level:'E3',observed_at:'2026-09-02T15:55:00Z',expires_at:'2026-09-02T17:00:00Z'},{...claim(),evidence_level:'E1'},{...claim(),expires_at:'2026-09-02T15:59:00Z'}]){const v=verify(envelope({body:{claims:{hsm:bad}}}),liveKey,fingerprints.live,'live_qualification');assert.equal(v.valid,true);assert.equal(verifiedClaim(v,'hsm',{levels:['E3'],now:NOW}),false)}})
test('legal privacy assurance has its own purpose and requires E4 claims',()=>{const env=envelope({key:legalKey,purpose:'legal_privacy_assurance',body:{claims:{brao_43e:claim('E4')}}});const v=verify(env,legalKey,fingerprints.legal,'legal_privacy_assurance');assert.equal(v.valid,true);assert.equal(verifiedClaim(v,'brao_43e',{levels:['E4'],now:NOW}),true)})
test('independent assurance uses separate purpose and requires E4 claims',()=>{const env=envelope({key:independentKey,purpose:'independent_assurance',body:{claims:{independent_pentest:claim('E4')}}});const v=verify(env,independentKey,fingerprints.independent,'independent_assurance');assert.equal(v.valid,true);assert.equal(verifiedClaim(v,'independent_pentest',{levels:['E4'],now:NOW}),true);assert.equal(verifiedClaim(v,'independent_pentest',{levels:['E3'],now:NOW}),false)})
test('runtime legal and independent assurance must use three distinct trust anchors',()=>{const live=verify(envelope(),liveKey,fingerprints.live,'live_qualification');const legal=verify(envelope({key:legalKey,purpose:'legal_privacy_assurance'}),legalKey,fingerprints.legal,'legal_privacy_assurance');const independent=verify(envelope({key:independentKey,purpose:'independent_assurance'}),independentKey,fingerprints.independent,'independent_assurance');assert.equal(trustAnchorsDistinct(live,legal,independent),true);const reused=verify(envelope({key:liveKey,purpose:'independent_assurance'}),liveKey,fingerprints.live,'independent_assurance');assert.equal(trustAnchorsDistinct(live,legal,reused),false)})
