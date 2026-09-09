import { readFile, mkdir, rm } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { join, resolve } from 'node:path'
import { collectLocalRepository } from '../self-service/local-collector.mjs'
import { buildProspectSecuritySignal, draftSecuritySignalMessage } from './lead-engine.mjs'

const targets=JSON.parse(await readFile(new URL('./targets.json',import.meta.url),'utf8'))
const outDir=resolve(process.argv[2]||'prospecting/evidence')
await mkdir(outDir,{recursive:true})
const results=[]
for(const target of targets){
  const slug=target.repository.replace('/','__')
  const dir=join(outDir,`repo-${slug}`)
  await rm(dir,{recursive:true,force:true})
  execFileSync('git',['clone','--depth','1','--filter=blob:none',`https://github.com/${target.repository}.git`,dir],{stdio:'ignore',timeout:120000})
  const snapshot=await collectLocalRepository(dir)
  snapshot.repository_url=`https://github.com/${target.repository}`
  const signal=buildProspectSecuritySignal(snapshot,{repository:snapshot.repository_url})
  const message=draftSecuritySignalMessage(signal,{name:'team'})
  results.push({...target,signal,message})
  await rm(dir,{recursive:true,force:true})
}
results.sort((a,b)=>b.signal.priority-a.signal.priority)
await BunWrite(join(outDir,'prospect-signals.json'),JSON.stringify({version:'trustready-prospect-batch/v1',generatedAt:new Date().toISOString(),targets:results.length,results},null,2)+'\n')
await BunWrite(join(outDir,'outreach-preview.md'),results.map((r,i)=>`# ${i+1}. ${r.repository}\n\n**Classification:** ${r.signal.classification} · priority ${r.signal.priority}\n\n**Observed effects:** ${r.signal.observed.effectClasses.join(', ')||'none'}\n\n**Observed controls:** ${r.signal.observed.controlClasses.join(', ')||'none'}\n\n## Draft\n\n${r.message}\n`).join('\n---\n\n'))
console.log(JSON.stringify(results.map(r=>({repository:r.repository,classification:r.signal.classification,priority:r.signal.priority,effects:r.signal.observed.effectClasses,controls:r.signal.observed.controlClasses,revision:r.signal.revision})),null,2))

async function BunWrite(path,data){ const {writeFile}=await import('node:fs/promises'); return writeFile(path,data,'utf8') }
