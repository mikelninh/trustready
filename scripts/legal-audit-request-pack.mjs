const deploymentId=process.argv[2]||'bao-legal-shadow'
const now=new Date().toISOString()
const sha='sha256:<64 lowercase hex digest of the underlying evidence artifact>'

const claim=(name,level,what,who,validity)=>({name,evidence_level:level,what_must_be_proven:what,expected_signer_role:who,evidence_hash:sha,observed_at:'<ISO-8601>',expires_at:`<ISO-8601; ${validity}>`})

const pack={
  schema:'trustready-legal-audit-request-pack-v1',
  deployment_id:deploymentId,
  generated_at:now,
  rule:'A claim is never accepted from this request pack itself. The reviewer must inspect the underlying evidence, compute its digest, issue the appropriate signed assurance envelope, and publish the public-key fingerprint through a separate trusted channel.',
  roles:{
    runtime_security:{
      purpose:'live_qualification',
      envelope_schema:'trustready-live-assurance-v1',
      maximum_envelope_lifetime:'24 hours',
      trust_env:['TRUSTREADY_LIVE_EVIDENCE','TRUSTREADY_LIVE_TRUST_KEY','TRUSTREADY_LIVE_TRUST_FINGERPRINT'],
      claims:[
        claim('hsm','E3','Live HSM/KMS key protection, algorithm, region, key state and a successful managed signing operation.','runtime/security evidence signer','short-lived'),
        claim('dlp','E3','Live DLP/PII scanner blocks a synthetic mandate-data canary and fails closed on scanner outage.','runtime/security evidence signer','short-lived'),
        claim('network','E3','Live workload has deny-by-default egress and reaches only the approved restricted endpoint through verified TLS/DNS path.','runtime/security evidence signer','short-lived'),
        claim('worm_locked','E3','Evidence store retention is irreversibly locked and a signed qualification artifact is stored under that lock.','runtime/security evidence signer','short-lived'),
        claim('secrets_manager','E3','Production secrets are sourced from the approved secrets manager and rotation/revocation was exercised.','runtime/security evidence signer','short-lived'),
        claim('backup_restore','E3','Encrypted backup exists and a dated restore exercise completed successfully.','runtime/security evidence signer','short-lived'),
        claim('deletion_test','E3','Applicable data deletion completed and produced a verifiable receipt/result.','runtime/security evidence signer','short-lived'),
        claim('incident_drill','E3','Kill switch / incident runbook was exercised and consequential actions remained blocked.','runtime/security evidence signer','short-lived'),
        claim('malware_scan','E3','Upload path uses malware/content scanning and blocks the positive canary corpus.','runtime/security evidence signer','short-lived'),
        claim('sbom_vulnerability','E3','Current deployed release has an SBOM and current vulnerability assessment with release-gate disposition.','runtime/security evidence signer','short-lived'),
        claim('web_session_scan','E3','Deployed user surface passes required session/security-header tests for the exact release.','runtime/security evidence signer','short-lived')
      ]
    },
    legal_privacy:{
      purpose:'legal_privacy_assurance',
      envelope_schema:'trustready-legal-privacy-assurance-v1',
      maximum_envelope_lifetime:'90 days',
      trust_env:['TRUSTREADY_LEGAL_EVIDENCE','TRUSTREADY_LEGAL_TRUST_KEY','TRUSTREADY_LEGAL_TRUST_FINGERPRINT'],
      claims:[
        claim('avv_dpa','E4','Executed/approved processor agreement covers the exact service and processing.','authorised legal/privacy reviewer','review-cycle bounded'),
        claim('brao_43e','E4','Documented BRAO §43e service-provider/confidentiality assessment for the exact workflow.','authorised German legal reviewer','review-cycle bounded'),
        claim('subprocessors','E4','Complete current subprocessor chain is reviewed and accepted.','authorised legal/privacy reviewer','review-cycle bounded'),
        claim('transfer_assessment','E4','International-transfer posture and safeguards are explicitly assessed, including a no-transfer conclusion where applicable.','authorised privacy reviewer','review-cycle bounded'),
        claim('vvt','E4','Current record of processing activities covers the exact deployment/use case.','authorised privacy reviewer','review-cycle bounded'),
        claim('dpia_dsfa','E4','DPIA/DSFA screening and, if required, assessment is completed and approved.','authorised privacy reviewer','review-cycle bounded'),
        claim('ai_act_classification','E4','EU AI Act role/use-case classification is recorded for the exact deployment.','authorised legal/AI governance reviewer','review-cycle bounded'),
        claim('ai_literacy','E4','Required users have current AI-literacy/training evidence.','authorised governance reviewer','review-cycle bounded')
      ]
    },
    independent_auditor:{
      purpose:'independent_assurance',
      envelope_schema:'trustready-independent-assurance-v1',
      maximum_envelope_lifetime:'90 days',
      trust_env:['TRUSTREADY_INDEPENDENT_EVIDENCE','TRUSTREADY_INDEPENDENT_TRUST_KEY','TRUSTREADY_INDEPENDENT_TRUST_FINGERPRINT'],
      claims:[
        claim('independent_pentest','E4','Independent penetration test covers the exact deployed service/release; critical/high findings are remediated or release-blocked.','independent security assessor','audit-cycle bounded'),
        claim('independent_legal_privacy_review','E4','Independent reviewer validates the legal/privacy evidence set and deployment assumptions.','independent German legal/privacy reviewer','audit-cycle bounded'),
        claim('independent_evidence_verification','E4','A clean reviewer context independently verifies evidence artifacts, hashes, signatures, trust anchors and claimed mappings.','independent assurance reviewer','audit-cycle bounded')
      ]
    }
  },
  separation_rules:[
    'The three assurance envelopes use different signature purposes.',
    'The three pinned trust-anchor fingerprints must be distinct.',
    'The evidence file must not carry or select its own trust anchor.',
    'The reviewer must verify the underlying artifact before signing its evidence hash.',
    'A numeric score can never override a missing mandatory claim.'
  ],
  final_command:'npm run audit:legal'
}

console.log(JSON.stringify(pack,null,2))
