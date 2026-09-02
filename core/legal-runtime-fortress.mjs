import crypto from 'node:crypto'
import {ZONES,authorizeMatter,parseTime,sha256,signEnvelope,verifyEnvelope,verifyIdentityAssertion,verifyMatterAuthorization} from './legal-key-identity.mjs'
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
  const v=verifyEnvelope({envelope:passport,key_store,purpose:'provider_review',now})
  if(!v.valid)return v
  const b=v.body
  if(b.schema!=='trustready-provider-passport-v2'||!b.policy_version||b.policy_version!==policy_version)return{valid:false,reason:'provider passport policy/schema version invalid'}
  if(b.status!=='approved'||parseTime(b.valid_until)<=now.getTime())return{valid:false,reason:'provider not currently approved'}
  if(b.training_on_customer_data!==false||!b.use_cases||typeof b.third_country!=='boolean')return{valid:false,reason:'provider training/use-case/transfer classification invalid'}
  if(b.third_country===true&&b.transfer_safeguards_status!=='approved')return{valid:false,reason:'third-country safeguards missing'}
  return{valid:true,body:b,signer_key_id:v.signer_key_id}
}

export function evaluateRuntimeState({state,tenant_id,provider_id,action=false}){
  if(!state||state.external_ai_enabled!==true)return{allowed:false,reason:'external AI kill switch is off'}
  if(state.disabled_tenants?.includes(tenant_id))return{allowed:false,reason:'tenant disabled'}
  if(state.disabled_providers?.includes(provider_id))return{allowed:false,reason:'provider disabled'}
  if(action&&state.outbound_actions_enabled!==true)return{allowed:false,reason:'outbound action kill switch is off'}
  return{allowed:true}
}

export function authorizeLegalEgress({identity_assertion,matter_authorization,dlp_attestation,request,provider_passport,key_store,runtime_state,network_probe,egress_enforcement_attestation,now=new Date()}){
  if(!request||!Object.hasOwn(ZONES,request.zone))return deny('INVALID_REQUEST','valid zone required',now)
  const state=evaluateRuntimeState({state:runtime_state,tenant_id:request.tenant_id,provider_id:request.provider_id})
  if(!state.allowed)return deny('KILL_SWITCH',state.reason,now)
  if(!productionTrustReady(runtime_state,key_store))return deny('ROOT_TRUST_REQUIRED','production requires a root-pinned signed keyring',now)
  if(!request.policy_version||runtime_state.policy_version!==request.policy_version)return deny('POLICY_VERSION_DENIED','active policy version mismatch',now)
  if(runtime_state.production===true&&(!runtime_state.release||typeof runtime_state.release!=='string'))return deny('RELEASE_REQUIRED','production release identity required',now)
  const enforced=verifyEgressEnforcement({attestation:egress_enforcement_attestation,key_store,tenant_id:request.tenant_id,policy_version:request.policy_version,release:runtime_state.release,now})
  if(!enforced.valid)return deny('EGRESS_ENFORCEMENT_DENIED',enforced.reason,now)
  const identity=verifyIdentityAssertion({assertion:identity_assertion,key_store,now})
  if(!identity.valid)return deny('IDENTITY_DENIED',identity.reason,now)
  if(identity.principal.session_id!==request.actor_session_id)return deny('SESSION_MISMATCH','session mismatch',now)
  const matter=authorizeMatter({principal:identity.principal,tenant_id:request.tenant_id,matter_id:request.matter_id,operation:'egress',zone:request.zone})
  if(!matter.allowed)return deny('MATTER_DENIED',matter.reason,now)
  let matterAuthSigner=null
  if(runtime_state.production===true&&ZONES[request.zone]>=ZONES.MANDATE){
    if(!request.matter_version)return deny('MATTER_VERSION_REQUIRED','production mandate egress requires current matter version',now)
    const fresh=verifyMatterAuthorization({authorization:matter_authorization,key_store,expected:{subject:identity.principal.subject,tenant_id:request.tenant_id,session_id:identity.principal.session_id,matter_id:request.matter_id,resource_version:request.matter_version},operation:'egress',now})
    if(!fresh.valid)return deny('FRESH_MATTER_AUTH_REQUIRED',fresh.reason,now)
    matterAuthSigner=fresh.signer_key_id
  }
  if(request.zone==='RESTRICTED')return deny('RESTRICTED_EXTERNAL_DENIED','Zone 4 external egress disabled by default',now)
  const providerV=verifyProviderPassport({passport:provider_passport,key_store,policy_version:request.policy_version,now})
  if(!providerV.valid)return deny('PROVIDER_DENIED',providerV.reason,now)
  const provider=providerV.body
  if(provider.provider_id!==request.provider_id)return deny('PROVIDER_MISMATCH','provider mismatch',now)
  const policy=provider.use_cases?.[request.use_case]
  if(!policy||!policy.allowed_zones?.includes(request.zone))return deny('USE_CASE_DENIED','use case/zone not approved',now)
  if(!request.region||!policy.regions?.includes(request.region))return deny('REGION_DENIED','explicit approved region required',now)
  if(provider.avv_status!=='approved'||provider.brao_43e_status!=='approved'||provider.subprocessor_status!=='approved')return deny('LEGAL_VENDOR_GAP','AVV/§43e/subprocessor approval incomplete',now)
  if(provider.third_country===true&&provider.transfer_safeguards_status!=='approved')return deny('TRANSFER_GAP','third-country safeguards missing',now)
  const retention=request.retention_minutes??0
  if(!Number.isInteger(retention)||retention<0||!Number.isInteger(policy.max_retention_minutes)||retention>policy.max_retention_minutes)return deny('RETENTION_DENIED','retention exceeds policy',now)
  if(!request.payload||typeof request.payload!=='object'||Array.isArray(request.payload))return deny('PAYLOAD_DENIED','structured payload required',now)
  const topFields=Object.keys(request.payload)
  if(!Array.isArray(policy.allowed_fields)||topFields.some(k=>!policy.allowed_fields.includes(k)))return deny('FIELD_DENIED','payload field outside signed use-case policy',now)
  const dlp=inspectPayload(request.payload,{allow_sensitive_keys:policy.allowed_sensitive_keys||[],max_payload_bytes:policy.max_payload_bytes||1024*1024})
  if(!dlp.safe)return deny('DLP_DENIED','payload contains identifier/secret or violates parser limits',now,{finding_types:[...new Set(dlp.findings.map(f=>f.type))]})
  let dlpSigner=null,dlpScanner=null
  if(runtime_state.production===true&&ZONES[request.zone]>=ZONES.MANDATE){
    if(!runtime_state.dlp_config_fingerprint)return deny('DLP_CONFIG_REQUIRED','production DLP configuration fingerprint required',now)
    const attested=verifyDlpAttestation({attestation:dlp_attestation,key_store,tenant_id:request.tenant_id,matter_id:request.matter_id,payload_fingerprint:dlp.fingerprint,policy_version:request.policy_version,scanner_config_fingerprint:runtime_state.dlp_config_fingerprint,now})
    if(!attested.valid)return deny('DLP_ATTESTATION_REQUIRED',attested.reason,now)
    dlpSigner=attested.signer_key_id
    dlpScanner=`${attested.scanner_id}@${attested.scanner_version}`
  }
  const network=evaluateNetworkEgress({endpoint:request.endpoint,provider,use_case:request.use_case,region:request.region,network_probe,key_store,expected_request_fingerprint:request.transport_request_fingerprint||null,now})
  if(!network.allowed)return deny('NETWORK_DENIED',network.reason,now)
  return{allowed:true,code:'ALLOW',decision_id:crypto.randomUUID(),decided_at:now.toISOString(),actor_id:identity.principal.subject,tenant_id:request.tenant_id,matter_id:request.matter_id||null,matter_version:request.matter_version||null,provider_id:request.provider_id,use_case:request.use_case,region:request.region,endpoint:network.endpoint,payload_fingerprint:dlp.fingerprint,payload_bytes:dlp.bytes,transport_request_fingerprint:request.transport_request_fingerprint||null,release:runtime_state.release||null,identity_signer:identity.signer_key_id,matter_auth_signer:matterAuthSigner,provider_signer:providerV.signer_key_id,dlp_signer:dlpSigner,dlp_scanner:dlpScanner,dlp_config_fingerprint:runtime_state.dlp_config_fingerprint||null,egress_enforcement_signer:enforced.signer_key_id,network_attestor:network.network_proof.attestor_key_id,peer_fingerprint:network.network_proof.peer_fingerprint}
}

const HASH=/^sha256:[0-9a-f]{64}$/
const OPAQUE=/^[A-Za-z0-9._:-]{1,128}$/
const ACTION_SCHEMAS={
  send_email:{required:['message_id','recipient_refs','subject_hash','body_hash','resource_version'],arrays:['recipient_refs'],hashes:['subject_hash','body_hash']},
  bea_send:{required:['message_id','recipient_refs','document_hashes','resource_version'],arrays:['recipient_refs','document_hashes'],hash_arrays:['document_hashes']},
  case_write:{required:['record_id','mutation','value_hash','resource_version'],hashes:['value_hash'],enum:{mutation:['set_note','set_status','attach_document']}},
  deadline_write:{required:['deadline_id','operation','deadline_hash','resource_version'],hashes:['deadline_hash'],enum:{operation:['create','update','cancel']}},
  complete_task:{required:['task_id','resource_version']}
}

export function validateActionPayload(action,payload){
  const s=ACTION_SCHEMAS[action]
  if(!s||!payload||typeof payload!=='object'||Array.isArray(payload))return{valid:false,reason:'unsupported action or invalid payload'}
  const allowed=new Set(s.required),keys=Object.keys(payload)
  if(s.required.some(k=>!(k in payload)))return{valid:false,reason:'required action field missing'}
  if(keys.some(k=>!allowed.has(k)))return{valid:false,reason:'unexpected action field'}
  for(const k of s.arrays||[])if(!Array.isArray(payload[k])||payload[k].length===0||payload[k].length>20)return{valid:false,reason:`${k} must be a non-empty bounded array`}
  for(const k of s.hashes||[])if(!HASH.test(payload[k]))return{valid:false,reason:`${k} must be sha256`}
  for(const k of s.hash_arrays||[])if(payload[k].some(v=>!HASH.test(v)))return{valid:false,reason:`${k} must contain sha256 values`}
  for(const[k,values]of Object.entries(s.enum||{}))if(!values.includes(payload[k]))return{valid:false,reason:`${k} value denied`}
  for(const[k,v]of Object.entries(payload)){
    if(k.endsWith('_id')||k==='resource_version'||k.endsWith('_refs')){
      if(Array.isArray(v)){
        if(v.some(x=>typeof x!=='string'||!OPAQUE.test(x)||x.includes('@')))return{valid:false,reason:`${k} contains unsafe reference`}
      }else if(typeof v!=='string'||!OPAQUE.test(v)||v.includes('@'))return{valid:false,reason:`${k} must be opaque`}
    }
  }
  return{valid:true,payload_hash:`sha256:${sha256(payload)}`}
}

export function issueActionApproval({identity_assertion,matter_authorization,key_store,tenant_id,matter_id,action,payload,policy_version,expires_at,private_key,key_id,production=false,now=new Date()}){
  if(production&&key_store?.rooted!==true)throw new Error('production requires root-pinned key trust')
  const id=verifyIdentityAssertion({assertion:identity_assertion,key_store,now})
  if(!id.valid||id.principal.tenant_id!==tenant_id||id.principal.mfa!==true)throw new Error('verified MFA identity required')
  if(!policy_version)throw new Error('active policy version required')
  const authAge=now.getTime()-parseTime(id.principal.auth_time)
  if(authAge<0||authAge>10*60*1000)throw new Error('recent step-up authentication required')
  const matter=authorizeMatter({principal:id.principal,tenant_id,matter_id,operation:'approve_action',zone:'MANDATE'})
  if(!matter.allowed)throw new Error(matter.reason)
  const schema=validateActionPayload(action,payload)
  if(!schema.valid)throw new Error(schema.reason)
  if(production){
    const fresh=verifyMatterAuthorization({authorization:matter_authorization,key_store,expected:{subject:id.principal.subject,tenant_id,session_id:id.principal.session_id,matter_id,resource_version:payload.resource_version},operation:'approve_action',now})
    if(!fresh.valid)throw new Error(`fresh matter authorization required: ${fresh.reason}`)
  }
  const expiry=parseTime(expires_at)
  if(expiry<=now.getTime()||expiry-now.getTime()>5*60*1000)throw new Error('approval lifetime must be >0 and <=5 minutes')
  const body={schema:'trustready-action-approval-v2',capability_id:crypto.randomUUID(),actor_id:id.principal.subject,actor_session_id:id.principal.session_id,tenant_id,matter_id,action,payload_hash:schema.payload_hash,resource_version:payload.resource_version,policy_version,issued_at:now.toISOString(),expires_at,nonce:crypto.randomBytes(32).toString('hex')}
  return signEnvelope({body,private_key,key_id,purpose:'action_approval'})
}

export async function executeApprovedAction({runtime_state,deployment_mode='shadow',tenant_id,policy_version}){
  if(!DEPLOYMENT_MODES.has(deployment_mode))return{executed:false,code:'DEPLOYMENT_MODE_DENIED',reason:'unknown deployment mode'}
  const state=evaluateRuntimeState({state:runtime_state,tenant_id,provider_id:'__actions__',action:true})
  if(!state.allowed)return{executed:false,code:'KILL_SWITCH',reason:state.reason}
  if(!policy_version||runtime_state?.policy_version!==policy_version)return{executed:false,code:'POLICY_VERSION_DENIED',reason:'active policy version mismatch'}
  if(deployment_mode==='shadow')return{executed:false,code:'SHADOW_LOCK',reason:'all outbound and write actions are disabled in shadow mode'}
  return{executed:false,code:'PRODUCTION_ACTIONS_DISABLED',reason:'production action execution is disabled until replay prevention and resource-version compare-and-write are service-owned, durable and atomic'}
}
