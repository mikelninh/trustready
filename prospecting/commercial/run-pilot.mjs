import { readFile, mkdir, rm, writeFile } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { join, resolve } from 'node:path'
import { collectLocalRepository } from '../../self-service/local-collector.mjs'
import { buildProspectSecuritySignalV22 } from '../v2/engine-v2.2.mjs'

const raw=JSON.parse(await readFile(new URL('./targets.json',import.meta.url),'utf8'))
const seen=new Set()
const targets=raw.filter(t=>{ if(seen.has(t.repository)) return false; seen.add(t.repository); return true })
const outDir=resolve(process.argv[2]||'prospecting/commercial/evidence')
await mkdir(outDir,{recursive:true})

function ageDays(iso){
  const ms=Date.now()-Date.parse(iso)
  return Number.isFinite(ms)?Math.max(0,Math.floor(ms/86400000)):9999
}
function commercialScore(target,signal,days){
  let score=0
  if(signal.classification==='PROOF_GAP') score+=45
  else if(signal.classification==='REVIEW_SIGNAL') score+=20
  else if(signal.classification==='ARCHITECTURE_UNCERTAIN') score+=5
  if(target.ownerType==='Organization') score+=15
  score+=Math.min(20,(target.commercialFit||0)*4)
  if(days<=30) score+=15
  else if(days<=90) score+=10
  else if(days<=180) score+=5
  const consequences=signal.evidence?.selectableConsequences||[]
  if(consequences.some(x=>/(email|message|payment|charge|refund|transfer|deploy|bash|shell|write|edit|delete|home)/i.test(`${x.toolName||''} ${x.implementationPath||''}`))) score+=5
  return Math.min(100,score)
}
function decision(signal,score){
  if(signal.classification==='PROOF_GAP' && score>=75) return 'HUMAN_REVIEW_FOR_OUTREACH'
  if(['PROOF_GAP','REVIEW_SIGNAL'].includes(signal.classification) && score>=55) return 'RESEARCH_MORE'
  return 'DO_NOT_OUTREACH'
}

const results=[]
for(const target of targets){
  const slug=target.repository.replace('/','__')
  const dir=join(outDir,`repo-${slug}`)
  await rm(dir,{recursive:true,force:true})
  try{
    execFileSync('git',['clone','--depth','1','--filter=blob:none',`https://github.com/${target.repository}.git`,dir],{stdio:'ignore',timeout:120000})
    const lastCommit=execFileSync('git',['-C',dir,'log','-1','--format=%cI'],{encoding:'utf8'}).trim()
    const daysSinceCommit=ageDays(lastCommit)
    const snapshot=await collectLocalRepository(dir)
    snapshot.repository_url=`https://github.com/${target.repository}`
    const signal=buildProspectSecuritySignalV22(snapshot,{repository:snapshot.repository_url,segment:target.segment})
    const score=commercialScore(target,signal,daysSinceCommit)
    results.push({...target,lastCommit,daysSinceCommit,signal,commercialScore:score,decision:decision(signal,score)})
  }catch(err){
    results.push({...target,error:String(err?.message||err),commercialScore:0,decision:'DO_NOT_OUTREACH'})
  }
  await rm(dir,{recursive:true,force:true})
}

const ranked=results.filter(x=>x.signal).sort((a,b)=>b.commercialScore-a.commercialScore)
const outreachQueue=ranked.filter(x=>x.decision==='HUMAN_REVIEW_FOR_OUTREACH')
const report={
  version:'trustready-commercial-prospect-pilot/v1',
  generatedAt:new Date().toISOString(),
  targets:targets.length,
  completed:results.filter(x=>x.signal).length,
  outreachQueue:outreachQueue.map(x=>({repository:x.repository,score:x.commercialScore,classification:x.signal.classification,lastCommit:x.lastCommit,revision:x.signal.revision,consequences:(x.signal.evidence?.selectableConsequences||[]).slice(0,5),truthBoundary:x.signal.truthBoundary})),
  ranked:ranked.map(x=>({repository:x.repository,score:x.commercialScore,decision:x.decision,classification:x.signal.classification,daysSinceCommit:x.daysSinceCommit,revision:x.signal.revision})),
  results,
  truthBoundary:'Commercial ranking is prioritization only. No outreach eligibility is automatic: every candidate requires human source review before contact. Passive public-source analysis only; no third-party execution or vulnerability claim.'
}
await writeFile(join(outDir,'commercial-prospect-report.json'),JSON.stringify(report,null,2)+'\n')
await writeFile(join(outDir,'outreach-review-queue.md'),outreachQueue.map((x,i)=>`# ${i+1}. ${x.repository}\n\n**Score ${x.commercialScore}/100 · ${x.signal.classification}**\n\nLast commit: ${x.lastCommit}\nRevision: \`${x.signal.revision}\`\n\n${x.signal.rationale}\n\nSelectable consequences:\n${(x.signal.evidence?.selectableConsequences||[]).slice(0,5).map(c=>`- ${c.toolName||c.implementationPath||'effect'} · ${c.kind}`).join('\n')||'- none'}\n\n**Status:** HUMAN REVIEW REQUIRED. Do not contact based on this report alone.\n`).join('\n---\n\n'))
console.log(JSON.stringify({targets:report.targets,completed:report.completed,outreachQueue:report.outreachQueue.length,top:report.ranked.slice(0,8)},null,2))
