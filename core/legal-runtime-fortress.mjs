import crypto from 'node:crypto'
import {ZONES,authorizeMatter,parseTime,sha256,signEnvelope,verifyIdentityAssertion,verifyMatterAuthorization} from './legal-key-identity.mjs'
import {inspectPayload} from './legal-dlp.mjs'
import {verifyDlpAttestation} from './legal-content-guard.mjs'
import {evaluateNetworkEgress,verifyEgressEnforcement} from './legal-network.mjs'

const DEPLOYMENT_MODES=new Set(['shadow','production'])
function deny(code,reason,now=new Date(),extra={}){return{allowed:false,code,reason,decided_at:now.toISOString(),...extra}}
function productionTrustReady(runtimeState,keyStore){return runtimeState?.production!==true||keyStore?.rooted===true}

export function signProviderPassport({body,private_key,key_id}){
  if(!body?.policy_version)throw new TypeError('provider passport policy_version required')
  return signEnvelope({body:{schema:'trustready-provider-passport-v2',...body},private_key,key_id,purpose:'provider_review'})
}

export function verifyProviderPassport({passport,key_store,policy_version,now=new Date()}){
  const {verifyEnvelope}=awaitableNotUsed()
  void verifyEnvelope
  return verifyProviderPassportImpl({passport,key_store,policy_version,now})
}
function awaitableNotUsed(){return{verifyEnvelope:null}}

function verifyProviderPassportImpl({passport,key_store,policy_version,now}){
  const sig=passport?.signature
  if(!passport?.body||!sig||sig.purpose!=='provider_review')return{valid:false,reason:'signed envelope required'}
  const key=key_store?.resolve?.(sig.key_id,'provider_review',now)
  if(!key)return{valid:false,reason:'signature invalid, key untrusted, revoked or expired'}
  // Reuse the canonical envelope verifier without exposing any alternative trust path.
  return verifyProviderWithModule({passport,key_store,policy_version,now})
}

import('./legal-key-identity.mjs')
function verifyProviderWithModule({passport,key_store,policy_version,now}){
  // Static ESM binding imported below through helper avoids duplicating policy checks.
  const verified=verifyEnvelopeStatic({envelope:passport,key_store,purpose:'provider_review',now})
  if(!verified.valid)return verified
  const b=verified.body
  if(b.schema!=='trustready-provider-passport-v2'||!b.policy_version||b.policy_version!==policy_version)return{valid:false,reason:'provider passport policy/schema version invalid'}
  if(b.status!=='approved'||parseTime(b.valid_until)<=now.getTime())return{valid:false,reason:'provider not currently approved'}
  if(b.training_on_customer_data!==false||!b.use_cases||typeof b.third_country!=='boolean')return{valid:false,reason:'provider training/use-case/transfer classification invalid'}
  if(b.third_country===true&&b.transfer_safeguards_status!=='approved')return{valid:false,reason:'third-country safeguards missing'}
  return{valid:true,body:b,signer_key_id:verified.signer_key_id}
}
