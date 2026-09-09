import { readFile, mkdir, rm, writeFile } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { join, resolve } from 'node:path'
import { collectLocalRepository } from '../self-service/local-collector.mjs'
import { buildProspectSecuritySignal, draftSecuritySignalMessage } from './lead-engine.mjs'

const targets=JSON.parse(await readFile(new URL('./targets.json',import.meta.url),'utf8'))
const outDir=resolve(process.argv[2]||'prospecting/evidence')
await mkdir(outDir,{recursive:true})
const results=[]
const failures=[]

for(const target of targets){
  const slug=target.repository.replace('/','__')
  const dir=join(outDir,`repo-${slug}`)
  await rm(dir,{recursive:true,force:true})
  try {
    execFileSync('git',['clone','--depth','1','--filter=blob:none',`https://github.com/${target.repository}.git`,dir],{stdio:'ignore',timeout:120000})
    const snapshot=await collectLocalRepository(dir)
    snapshot.repository_url=`https://github.com/${target.repository}`
    const signal=buildProspectSecuritySignal(snapshot,{repository:snapshot.repository_url})
    const message=draftSecuritySignalMessage(signal,{name:'team'})
    const humanReviewRequired=['PROOF_GAP','REVIEW_SIGNAL'].includes(signal.classification)
    results.push({...target,signal,message,humanReviewRequired})
  } catch(error) {
    failures.push({repository:target.repository,error:String(error?.message||error)})
  } finally {
    await rm(dir,{recursive:true,force:true})
  }
}

results.sort((a,b)=>b.signal.priority-a.signal.priority)
const counts=results.reduce((m,x)=>(m[x.signal.classification]=(m[x.signal.classification]||0)+1,m),{})
const reviewQueue=results.filter(x=>x.humanReviewRequired).map(x=>({
  repository:x.repository,
  classification:x.signal.classification,
  priority:x.signal.priority,
  revision:x.signal.revision,
  directDispatchPaths:x.signal.observed.directDispatchPaths||[],
  effects:x.signal.observed.effectClasses,
  controls:x.signal.observed.controlClasses,
  rationale:x.signal.rationale,
}))
const rejected=results.filter(x=>!x.humanReviewRequired).length
const report={
  version:'trustready-prospect-batch/v2',
  generatedAt:new Date().toISOString(),
  targets:targets.length,
  completed:results.length,
  failures,
  metrics:{
    classifications:counts,
    humanReviewQueue:reviewQueue.length,
    rejectedBeforeHumanReview:rejected,
    rejectionRate:results.length?Number((rejected/results.length).toFixed(3)):0,
  },
  reviewQueue,
  results,
}
await writeFile(join(outDir,'prospect-signals.json'),JSON.stringify(report,null,2)+'\n','utf8')
await writeFile(join(outDir,'human-review-queue.json'),JSON.stringify(reviewQueue,null,2)+'\n','utf8')
await writeFile(join(outDir,'outreach-preview.md'),results
  .filter(r=>r.message)
  .map((r,i)=>`# ${i+1}. ${r.repository}\n\n**Classification:** ${r.signal.classification} · priority ${r.signal.priority}\n\n**Revision:** ${r.signal.revision}\n\n**Direct dispatch paths:** ${(r.signal.observed.directDispatchPaths||[]).join(', ')||'none'}\n\n**Observed effects:** ${r.signal.observed.effectClasses.join(', ')||'none'}\n\n**Observed controls:** ${r.signal.observed.controlClasses.join(', ')||'none'}\n\n**HUMAN REVIEW REQUIRED BEFORE SEND**\n\n## Draft\n\n${r.message}\n`).join('\n---\n\n'),'utf8')
console.log(JSON.stringify({metrics:report.metrics,failures,reviewQueue,results:results.map(r=>({repository:r.repository,classification:r.signal.classification,priority:r.signal.priority,effects:r.signal.observed.effectClasses,controls:r.signal.observed.controlClasses,directDispatchPaths:r.signal.observed.directDispatchPaths,revision:r.signal.revision}))},null,2))
