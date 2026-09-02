import {spawnSync} from 'node:child_process'
import fs from 'node:fs'
import {loadPinnedAssuranceFromEnv,trustAnchorsDistinct,verifiedClaim} from '../core/legal-assurance-evidence.mjs'

function run(command,args){const r=spawnSync(command,args,{encoding:'utf8',env:{...process.env,NO_COLOR:'1'}});return{ok:r.status===0,status:r.status,stdout:r.stdout||'',stderr:r.stderr||''}}
function findInt(text,re){const m=text.match(re);return m?Number(m[1]):null}
function parseLastJson(text){const start=text.lastIndexOf('\n{');const raw=(start>=0?text.slice(start+1):text).trim();try{return JSON.parse(raw)}catch{return null}}

const legalTestFiles=[
  'core/legal-assurance-evidence.test.mjs','core/legal-evidence.test.mjs','core/legal-gcp-bound-transport.test.mjs','core/legal-gcp-iac.test.mjs',
  'core/legal-gcp-infrastructure.test.mjs','core/legal-gcp-network-probe.test.mjs','core/legal-gcp-runtime-pipeline.test.mjs','core/legal-gcp-worm-bundle.test.mjs',
  'core/legal-production-gates.test.mjs','core/legal-replay-store.test.mjs','core/legal-runtime-fortress.test.mjs'
]
const tests=run(process.execPath,['--test',...legalTestFiles])
const benchmark=run(process.execPath,['benchmarks/run-scanner-benchmark.mjs'])
const benchmarkJson=parseLastJson(benchmark.stdout)
const pass=findInt(tests.stdout,/# pass (\d+)/),fail=findInt(tests.stdout,/# fail (\d+)/)

const requiredFiles=[
  'architecture/legal-control-matrix.md','architecture/legal-evidence-pack.md','architecture/legal-trust-standard.md',
  'core/legal-runtime-fortress.mjs','core/legal-dlp.mjs','core/legal-network.mjs','core/legal-evidence.mjs','core/legal-assurance-evidence.mjs',
  'core/legal-gcp-bound-transport.mjs','core/legal-vertex-proposal.mjs','core/legal-gcp-runtime-pipeline.mjs',
  'infra/gcp-legal-shadow/main.tf','infra/gcp-legal-shadow/README.md'
]
const filesPresent=requiredFiles.every(p=>fs.existsSync(p))
const regressionNames=[
  'self-authored booleans and unsigned JSON cannot become audit evidence',
  'attacker signature fails against pinned auditor key',
  'runtime legal and independent assurance must use three distinct trust anchors',
  'evidence context rejects direct or human-readable identifiers',
  'latest signed checkpoint detects suffix truncation of an otherwise valid chain',
  'bound transport attests full target plus exact body and sends over same TLS socket once',
  'same body on a different target path gets a different signed transport fingerprint',
  'bound transport fails closed on DNS poison invalid TLS peer or non-http1 session',
  'bound transport rejects socket substitution and redirects',
  'VPC Service Controls project identity is derived from project_id rather than caller-supplied number',
  'ECDSA HSM-style envelope verification matches Cloud KMS SHA-256 semantics',
  'Sensitive Data Protection scanner pins config and fails closed on malformed response, PII or outage',
  'network enforcement is scoped to exact VPC and rejects selectors, escapes and public IPs',
  'end-to-end qualification requires four purpose-separated HSM CryptoKeys plus DLP network and WORM proof',
  'full GCP mandate shadow pipeline sends proposal-only bytes on attested socket then commits evidence',
  'HSM CryptoKey reuse including network transport blocks pipeline before egress',
  'DNS poisoning blocks connection-bound transport before legal egress',
  'socket substitution or redirect cannot become CANDIDATE',
  'invalid or tool-shaped model output is rejected before WORM commit',
  'production needs independent DLP attestation for exact payload policy and scanner config',
  'production egress proof is bound to exact deployment release',
  'prototype property zone names cannot bypass mandate controls',
  'DLP detects nested unicode base64url identifiers and parser abuse',
  'stale provider passport and stale release proof are revoked',
  'shadow and production action execution cannot reach caller replay stores or handlers',
  'unknown action deployment mode fails closed before callbacks'
]
const missingRegressions=regressionNames.filter(name=>!tests.stdout.includes(name))
const regressionsPresent=missingRegressions.length===0
const fortressText=fs.existsSync('core/legal-runtime-fortress.mjs')?fs.readFileSync('core/legal-runtime-fortress.mjs','utf8'):''
const productionActionsPhysicallyBlocked=fortressText.includes("code:'PRODUCTION_ACTIONS_DISABLED'")&&!fortressText.includes("return{executed:true,code:'EXECUTED'")
const now=new Date()

const liveAssurance=loadPinnedAssuranceFromEnv({evidence_env:'TRUSTREADY_LIVE_EVIDENCE',key_env:'TRUSTREADY_LIVE_TRUST_KEY',fingerprint_env:'TRUSTREADY_LIVE_TRUST_FINGERPRINT',purpose:'live_qualification',now})
const legalAssurance=loadPinnedAssuranceFromEnv({evidence_env:'TRUSTREADY_LEGAL_EVIDENCE',key_env:'TRUSTREADY_LEGAL_TRUST_KEY',fingerprint_env:'TRUSTREADY_LEGAL_TRUST_FINGERPRINT',purpose:'legal_privacy_assurance',now})
const independentAssurance=loadPinnedAssuranceFromEnv({evidence_env:'TRUSTREADY_INDEPENDENT_EVIDENCE',key_env:'TRUSTREADY_INDEPENDENT_TRUST_KEY',fingerprint_env:'TRUSTREADY_INDEPENDENT_TRUST_FINGERPRINT',purpose:'independent_assurance',now})

const liveRequired=['hsm','dlp','network','worm_locked','secrets_manager','backup_restore','deletion_test','incident_drill','malware_scan','sbom_vulnerability','web_session_scan']
const liveObserved=liveRequired.filter(k=>verifiedClaim(liveAssurance,k,{levels:['E3','E4'],now}))
const liveComplete=liveAssurance.valid&&liveObserved.length===liveRequired.length
const legalRequired=['avv_dpa','brao_43e','subprocessors','transfer_assessment','vvt','dpia_dsfa','ai_act_classification','ai_literacy']
const legalObserved=legalRequired.filter(k=>verifiedClaim(legalAssurance,k,{levels:['E4'],now}))
const legalComplete=legalAssurance.valid&&legalObserved.length===legalRequired.length
const independentRequired=['independent_pentest','independent_legal_privacy_review','independent_evidence_verification']
const independentObserved=independentRequired.filter(k=>verifiedClaim(independentAssurance,k,{levels:['E4'],now}))
const independentEvidenceComplete=independentAssurance.valid&&independentObserved.length===independentRequired.length
const distinctTrustAnchors=trustAnchorsDistinct(liveAssurance,legalAssurance,independentAssurance)
const independentComplete=independentEvidenceComplete&&distinctTrustAnchors

const engineering=tests.ok&&fail===0&&filesPresent&&regressionsPresent&&productionActionsPhysicallyBlocked&&benchmark.ok&&benchmarkJson?.release_gate?.false_verified_zero===true&&benchmarkJson?.release_gate?.verified_recall_complete===true&&benchmarkJson?.release_gate?.exact_status_complete===true&&benchmarkJson?.release_gate?.provenance_complete===true
const report={
  schema:'trustready-legal-preaudit-v4',generated_at:now.toISOString(),
  engineering:{status:engineering?'PASS':'FAIL',legal_tests:{pass,fail},regression_findings_closed:regressionsPresent,missing_regressions:missingRegressions,production_actions_physically_blocked:productionActionsPhysicallyBlocked,scanner:benchmarkJson?.metrics||null},
  live_runtime:{status:liveComplete?'PASS':'MISSING_EVIDENCE',assurance_signature_valid:liveAssurance.valid,trust_fingerprint:liveAssurance.valid?liveAssurance.trust_fingerprint:null,reason:liveAssurance.valid?null:liveAssurance.reason,required:liveRequired,observed:liveObserved},
  legal_governance:{status:legalComplete?'PASS':'MISSING_EVIDENCE',assurance_signature_valid:legalAssurance.valid,trust_fingerprint:legalAssurance.valid?legalAssurance.trust_fingerprint:null,reason:legalAssurance.valid?null:legalAssurance.reason,required:legalRequired,observed:legalObserved},
  independent_assurance:{status:independentComplete?'PASS':'MISSING_EVIDENCE',assurance_signature_valid:independentAssurance.valid,trust_fingerprint:independentAssurance.valid?independentAssurance.trust_fingerprint:null,reason:independentAssurance.valid?null:independentAssurance.reason,required:independentRequired,observed:independentObserved,distinct_trust_anchors:distinctTrustAnchors},
  verdict:{pre_audit_ready:engineering,real_mandate_shadow_ready:engineering&&liveComplete&&legalComplete&&independentComplete,independently_assured:engineering&&liveComplete&&legalComplete&&independentComplete},blockers:[]
}
if(!engineering)report.blockers.push('engineering or regression evidence failed')
if(!liveComplete)report.blockers.push('cryptographically trusted live runtime operating evidence incomplete')
if(!legalComplete)report.blockers.push('separately signed legal/privacy governance evidence incomplete')
if(!independentEvidenceComplete)report.blockers.push('separately signed independent penetration/legal/privacy/evidence verification incomplete')
if(independentEvidenceComplete&&!distinctTrustAnchors)report.blockers.push('runtime, legal/privacy and independent assurance trust anchors must be distinct')
console.log(JSON.stringify(report,null,2))
process.exit(report.verdict.pre_audit_ready?0:1)
