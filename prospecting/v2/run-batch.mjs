import { readFile, mkdir, rm, writeFile } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { join, resolve } from 'node:path'
import { collectLocalRepository } from '../../self-service/local-collector.mjs'
import { buildProspectSecuritySignalV2, precisionMetrics } from './engine-v2.mjs'

const targets=JSON.parse(await readFile(new URL('./targets.json',import.meta.url),'utf8'))
const labelsPath=new URL('./human-labels.json',import.meta.url)
let labels={}
try{ labels=JSON.parse(await readFile(labelsPath,'utf8')) }catch{}
const outDir=resolve(process.argv[2]||'prospecting/v2/evidence')
await mkdir(outDir,{recursive:true})
const results=[]
for(const target of targets){
  const slug=target.repository.replace('/','__')
  const dir=join(outDir,`repo-${slug}`)
  await rm(dir,{recursive:true,force:true})
  let cloneError=null
  try{
    execFileSync('git',['clone','--depth','1','--filter=blob:none',`https://github.com/${target.repository}.git`,dir],{stdio:'ignore',timeout:120000})
    const snapshot=await collectLocalRepository(dir)
    snapshot.repository_url=`https://github.com/${target.repository}`
    const signal=buildProspectSecuritySignalV2(snapshot,{repository:snapshot.repository_url,segment:target.segment})
    results.push({...target,signal,humanLabel:labels[target.repository]?.label||null,humanNote:labels[target.repository]?.note||null})
  }catch(err){ cloneError=String(err?.message||err); results.push({...target,cloneError,humanLabel:null,signal:null}) }
  await rm(dir,{recursive:true,force:true})
}
const completed=results.filter(x=>x.signal)
const queue=completed.filter(x=>x.signal.reviewRequired).sort((a,b)=>b.signal.priority-a.signal.priority)
const metrics=precisionMetrics(completed)
const distribution={}
for(const r of completed) distribution[r.signal.classification]=(distribution[r.signal.classification]||0)+1
const report={version:'trustready-prospect-v2-batch/v1',generatedAt:new Date().toISOString(),targets:targets.length,completed:completed.length,failed:results.length-completed.length,distribution,reviewQueue:queue.map(x=>({repository:x.repository,classification:x.signal.classification,priority:x.signal.priority,revision:x.signal.revision,flows:x.signal.evidence.selectorFlows.slice(0,3)})),precision:metrics,results}
await writeFile(join(outDir,'prospect-v2-report.json'),JSON.stringify(report,null,2)+'\n')
await writeFile(join(outDir,'human-review-queue.md'),queue.map((x,i)=>`# ${i+1}. ${x.repository}\n\n**${x.signal.classification} · ${x.signal.priority}**\n\nRevision: \`${x.signal.revision}\`\n\n${x.signal.rationale}\n\n${x.signal.evidence.selectorFlows.slice(0,3).map(f=>`- \`${f.path}:${f.selectorLine} → ${f.sinkLine}\` · role=${f.role} · localAuthorityControl=${f.localAuthorityControl}`).join('\n')||'- no selector flow'}\n`).join('\n---\n\n'))
console.log(JSON.stringify({targets:report.targets,completed:report.completed,distribution,reviewQueue:queue.length,precision:metrics},null,2))
