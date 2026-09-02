import fs from 'node:fs'
import {createKeyTrustStore,parseTime,publicKeyFingerprint,verifyEnvelope} from './legal-key-identity.mjs'

const HASH=/^sha256:[0-9a-f]{64}$/
const PURPOSES=new Set(['live_qualification','legal_privacy_assurance','independent_assurance'])
const LEVELS=new Set(['E3','E4'])
const SCHEMAS={
  live_qualification:'trustready-live-assurance-v1',
  legal_privacy_assurance:'trustready-legal-privacy-assurance-v1',
  independent_assurance:'trustready-independent-assurance-v1',
}

export function verifyAssuranceEnvelope({envelope,trusted_public_key,expected_fingerprint,purpose,now=new Date()}){
  if(!PURPOSES.has(purpose))return{valid:false,reason:'unsupported assurance purpose'}
  if(!trusted_public_key||!expected_fingerprint)return{valid:false,reason:'external pinned trust anchor required'}
  let fingerprint
  try{fingerprint=publicKeyFingerprint(trusted_public_key)}catch{return{valid:false,reason:'assurance trust key invalid'}}
  if(fingerprint!==expected_fingerprint)return{valid:false,reason:'assurance trust fingerprint mismatch'}
  const keyId=envelope?.signature?.key_id
  if(!keyId)return{valid:false,reason:'assurance signer key id required'}
  const store=createKeyTrustStore([{key_id:keyId,purpose,public_key:trusted_public_key}])
  const verified=verifyEnvelope({envelope,key_store:store,purpose,now})
  if(!verified.valid)return{valid:false,reason:verified.reason}
  const body=verified.body
  if(body?.schema!==SCHEMAS[purpose]||!body.deployment_id||!body.generated_at||!body.expires_at||!body.claims||typeof body.claims!=='object'||Array.isArray(body.claims))return{valid:false,reason:'assurance body schema incomplete'}
  let generated,expires
  try{generated=parseTime(body.generated_at);expires=parseTime(body.expires_at)}catch{return{valid:false,reason:'assurance timestamps invalid'}}
  if(generated>now.getTime()+5000||expires<=now.getTime())return{valid:false,reason:'assurance evidence stale or future-dated'}
  const maxLifetime=purpose==='live_qualification'?24*60*60*1000:90*24*60*60*1000
  if(expires-generated>maxLifetime)return{valid:false,reason:'assurance validity window too long'}
  return{valid:true,body,signer_key_id:verified.signer_key_id,trust_fingerprint:fingerprint,purpose}
}

export function verifiedClaim(assurance,name,{levels=['E3','E4'],now=new Date()}={}){
  if(!assurance?.valid)return false
  const claim=assurance.body.claims?.[name]
  if(!claim||claim.verified!==true||!LEVELS.has(claim.evidence_level)||!levels.includes(claim.evidence_level)||!HASH.test(claim.evidence_hash||''))return false
  try{
    const observed=parseTime(claim.observed_at),expires=parseTime(claim.expires_at)
    if(observed>now.getTime()+5000||expires<=now.getTime()||expires<observed)return false
  }catch{return false}
  return true
}

export function trustAnchorsDistinct(...assurances){
  if(assurances.some(a=>!a?.valid||!a.trust_fingerprint))return false
  const fingerprints=assurances.map(a=>a.trust_fingerprint)
  return new Set(fingerprints).size===fingerprints.length
}

// A local pre-audit can verify evidence completeness, but it cannot establish
// organisational independence about itself. Even perfect locally supplied E4
// envelopes therefore may only advance to an external-verdict candidate.
export function evaluateLocalPromotionGates({engineering=false,live_complete=false,legal_complete=false,independent_evidence_complete=false,distinct_trust_anchors=false,organizational_independence_claim=false}={}){
  const candidateForExternalVerdict=Boolean(engineering&&live_complete&&legal_complete&&independent_evidence_complete&&distinct_trust_anchors&&organizational_independence_claim)
  return{
    pre_audit_ready:Boolean(engineering),
    candidate_for_external_assurance:candidateForExternalVerdict,
    external_final_verdict_required:true,
    real_mandate_shadow_ready:false,
    independently_assured:false,
  }
}

export function loadPinnedAssuranceFromEnv({evidence_env,key_env,fingerprint_env,purpose,now=new Date(),env=process.env}){
  const evidencePath=env[evidence_env],keyPath=env[key_env],expectedFingerprint=env[fingerprint_env]
  if(!evidencePath&&!keyPath&&!expectedFingerprint)return{valid:false,reason:'assurance evidence not supplied',missing:true,purpose}
  if(!evidencePath||!keyPath||!expectedFingerprint)return{valid:false,reason:'evidence, trust key and pinned fingerprint must all be supplied',purpose}
  try{
    const envelope=JSON.parse(fs.readFileSync(evidencePath,'utf8'))
    const publicKey=fs.readFileSync(keyPath,'utf8')
    return verifyAssuranceEnvelope({envelope,trusted_public_key:publicKey,expected_fingerprint:expectedFingerprint,purpose,now})
  }catch{return{valid:false,reason:'assurance evidence or trust key unreadable',purpose}}
}
