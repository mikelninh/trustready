import {spawnSync} from 'node:child_process'
import fs from 'node:fs'

function run(command,args){
  const r=spawnSync(command,args,{encoding:'utf8',env:{...process.env,NO_COLOR:'1'}})
  return{ok:r.status===0,status:r.status,stdout:r.stdout||'',stderr:r.stderr||''}
}
function findInt(text,re){const m=text.match(re);return m?Number(m[1]):null}
function parseLastJson(text){const start=text.lastIndexOf('\n{');const raw=(start>=0?text.slice(start+1):text).trim();try{return JSON.parse(raw)}catch{return null}}

const tests=run(process.execPath,['--test','core/legal-evidence.test.mjs','core/legal-gcp-iac.test.mjs','core/legal-gcp-infrastructure.test.mjs','core/legal-gcp-network-probe.test.mjs','core/legal-gcp-runtime-pipeline.test.mjs','core/legal-gcp-worm-bundle.test.mjs','core/legal-production-gates.test.mjs','core/legal-replay-store.test.mjs','core/legal-runtime-fortress.test.mjs'])
const benchmark=run(process.execPath,['benchmarks/run-scanner-benchmark.mjs'])
const benchmarkJson=parseLastJson(benchmark.stdout)
const pass=findInt(tests.stdout,/# pass (\d+)/),fail=findInt(tests.stdout,/# fail (\d+)/)

const requiredFiles=[
  'architecture/legal-control-matrix.md','architecture/legal-evidence-pack.md','architecture/legal-trust-standard.md',
  'core/legal-runtime-fortress.mjs','core/legal-dlp.mjs','core/legal-network.mjs','core/legal-evidence.mjs',
  'infra/gcp-legal-shadow/main.tf','infra/gcp-legal-shadow/README.md'
]
const filesPresent=requiredFiles.every(p=>fs.existsSync(p))
const regressionNames=[
  'evidence context rejects direct or human-readable identifiers',
  'DLP detects nested, unicode/base64-obfuscated secrets and parser depth abuse',
  'prototype property zone names cannot bypass mandate controls',
  'network egress blocks wrong host, http, redirect, absent, unknown redirect or forged attestation',
  'stale provider passport is revoked by active policy version'
]
const regressionsPresent=regressionNames.every(name=>tests.stdout.includes(name))

let liveEvidence=null
if(process.env.TRUSTREADY_LIVE_EVIDENCE){
  try{liveEvidence=JSON.parse(fs.readFileSync(process.env.TRUSTREADY_LIVE_EVIDENCE,'utf8'))}catch{}
}
const liveRequired=['hsm','dlp','network','worm_locked','secrets_manager','backup_restore','deletion_test','incident_drill','malware_scan','sbom_vulnerability','web_session_scan']
const liveComplete=!!liveEvidence&&liveRequired.every(k=>liveEvidence[k]?.verified===true)
const legalRequired=['avv_dpa','brao_43e','subprocessors','transfer_assessment','vvt','dpia_dsfa','ai_act_classification','ai_literacy']
const legalComplete=!!liveEvidence&&legalRequired.every(k=>liveEvidence[k]?.verified===true)
const independentComplete=!!liveEvidence&&liveEvidence.independent_pentest?.verified===true&&liveEvidence.independent_legal_privacy_review?.verified===true&&liveEvidence.independent_evidence_verification?.verified===true

const engineering=tests.ok&&fail===0&&filesPresent&&regressionsPresent&&benchmark.ok&&benchmarkJson?.release_gate?.false_verified_zero===true&&benchmarkJson?.release_gate?.verified_recall_complete===true&&benchmarkJson?.release_gate?.exact_status_complete===true&&benchmarkJson?.release_gate?.provenance_complete===true
const report={
  schema:'trustready-legal-preaudit-v1',
  generated_at:new Date().toISOString(),
  engineering:{status:engineering?'PASS':'FAIL',legal_tests:{pass,fail},regression_findings_closed:regressionsPresent,scanner:benchmarkJson?.metrics||null},
  live_runtime:{status:liveComplete?'PASS':'MISSING_EVIDENCE',required:liveRequired,observed:liveEvidence?liveRequired.filter(k=>liveEvidence[k]?.verified===true):[]},
  legal_governance:{status:legalComplete?'PASS':'MISSING_EVIDENCE',required:legalRequired,observed:liveEvidence?legalRequired.filter(k=>liveEvidence[k]?.verified===true):[]},
  independent_assurance:{status:independentComplete?'PASS':'MISSING_EVIDENCE'},
  verdict:{
    pre_audit_ready:engineering,
    real_mandate_shadow_ready:engineering&&liveComplete&&legalComplete&&independentComplete,
    independently_assured:engineering&&liveComplete&&legalComplete&&independentComplete,
  },
  blockers:[]
}
if(!engineering)report.blockers.push('engineering or regression evidence failed')
if(!liveComplete)report.blockers.push('live runtime operating evidence incomplete')
if(!legalComplete)report.blockers.push('legal/privacy governance evidence incomplete')
if(!independentComplete)report.blockers.push('independent penetration/legal/privacy/evidence verification incomplete')
console.log(JSON.stringify(report,null,2))
process.exit(report.verdict.pre_audit_ready?0:1)
