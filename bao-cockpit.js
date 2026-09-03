import { GOLDEN_CASES } from './golden-cases.js'

const stateLabels = { INCOMPLETE: 'Unvollständig', REVIEW: 'Prüfen', READY: 'Zur Freigabe', DONE: 'Erledigt' }
const stateOrder = ['INCOMPLETE','REVIEW','READY','DONE']
let selectedId = GOLDEN_CASES[0].id
let activeFilter = 'ALL'
let meetingStep = 0
const localState = new Map(GOLDEN_CASES.map(c => [c.id, c.state]))
const outcomes = new Map()

const $ = (id) => document.getElementById(id)
const esc = (v='') => String(v).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))

function filteredCases(){
  return GOLDEN_CASES.filter(c => activeFilter === 'ALL' || localState.get(c.id) === activeFilter)
}

function renderQueue(){
  const list = $('caseList')
  list.innerHTML = filteredCases().map(c => {
    const st = localState.get(c.id)
    return `<button class="caseCard ${c.id===selectedId?'active':''}" data-case="${c.id}">
      <div class="caseTop"><span class="caseId">${c.id}</span><span class="urgency ${c.urgency==='HIGH'?'high':''}">${c.urgency==='HIGH'?'hoch':'normal'}</span></div>
      <strong>${esc(c.title)}</strong><small>${esc(c.client_label)} · ${esc(c.category)}</small>
      <div class="caseState ${st.toLowerCase()}">${stateLabels[st]}</div>
    </button>`
  }).join('')
  list.querySelectorAll('[data-case]').forEach(btn => btn.addEventListener('click', () => { selectedId = btn.dataset.case; renderAll() }))
}

function renderFilters(){
  document.querySelectorAll('[data-filter]').forEach(btn => {
    const f = btn.dataset.filter
    const count = f==='ALL' ? GOLDEN_CASES.length : [...localState.values()].filter(v=>v===f).length
    btn.textContent = `${f==='ALL'?'Alle':stateLabels[f]} · ${count}`
    btn.classList.toggle('active', activeFilter===f)
  })
}

function currentCase(){ return GOLDEN_CASES.find(c => c.id === selectedId) }

function renderDetail(){
  const c = currentCase(); if(!c) return
  const st = localState.get(c.id)
  $('detailTitle').textContent = c.title
  $('detailMeta').textContent = `${c.client_label} · ${c.category} · ${stateLabels[st]}`
  $('vnOriginal').textContent = c.vn_original
  $('deTranslation').textContent = c.de_translation
  $('summary').textContent = c.summary
  $('nextAction').textContent = c.next_action
  $('openPoints').innerHTML = c.open_points.length ? c.open_points.map(x=>`<li>${esc(x)}</li>`).join('') : '<li class="goodText">Keine offenen Punkte.</li>'
  $('documents').innerHTML = c.documents.length ? c.documents.map(([n,s])=>`<div class="docRow"><span>${esc(n)}</span><b>${esc(s)}</b></div>`).join('') : '<div class="docRow"><span>Keine Dokumente im synthetischen Fall</span><b>—</b></div>'
  $('timeline').innerHTML = c.timeline.map((x,i)=>`<div class="timelineItem"><span>${i+1}</span><p>${esc(x)}</p></div>`).join('')
  renderActions(c, st)
}

function renderActions(c, st){
  const box = $('actions')
  const buttons = []
  if(st==='INCOMPLETE') buttons.push(['Fehlende Unterlagen / Angaben anfordern','request'])
  if(st==='REVIEW') buttons.push(['Quellen manuell prüfen','review'])
  if(st==='INCOMPLETE' || st==='REVIEW') buttons.push(['Vorgang nach Prüfung zur Freigabe vorlegen','ready'])
  if(st==='READY') buttons.push(['Vorgang fachlich freigeben','approve'],['Korrektur erforderlich','edit'],['Vorgang ablehnen','reject'])
  if(st==='DONE') buttons.push(['Ergebnis ansehen','noop'])
  box.innerHTML = buttons.map(([label,act],i)=>`<button data-action="${act}" class="${i===0?'primary':''}">${label}</button>`).join('') + `<button disabled>Freigeben & senden — späterer Release</button>`
  box.querySelectorAll('[data-action]').forEach(btn=>btn.addEventListener('click',()=>handleAction(btn.dataset.action,c)))
}

function handleAction(action,c){
  if(action==='request') {
    $('actionResult').textContent = 'Rückfrage wurde lokal vorbereitet (VI-first). Im Rehearsal wird nichts versendet.'
  } else if(action==='review') {
    $('actionResult').textContent = 'Quellen bleiben nebeneinander sichtbar. Keine Angabe wird automatisch als wahr übernommen.'
  } else if(action==='ready') {
    localState.set(c.id,'READY'); $('actionResult').textContent = 'Vorgang liegt jetzt klar bei Bao zur fachlichen Freigabe.'
  } else if(action==='approve') {
    localState.set(c.id,'DONE'); outcomes.set(c.id,'accepted'); $('actionResult').textContent = 'Fachlich freigegeben. Rehearsal beendet hier — kein Versand.'
  } else if(action==='edit') {
    outcomes.set(c.id,'edited'); $('actionResult').textContent = 'Als Korrektur markiert. Im echten Pilot messen wir Bearbeitungszeit und Änderungsgrund.'
  } else if(action==='reject') {
    outcomes.set(c.id,'rejected'); localState.set(c.id,'DONE'); $('actionResult').textContent = 'Abgelehnt. Kein externer Schritt wurde ausgeführt.'
  }
  $('actionResult').classList.add('show')
  renderAll()
}

function renderMetrics(){
  const reviewed = [...outcomes.keys()].length
  const accepted = [...outcomes.values()].filter(v=>v==='accepted').length
  const edited = [...outcomes.values()].filter(v=>v==='edited').length
  const useful = accepted + edited
  const sample = reviewed ? GOLDEN_CASES.filter(c=>outcomes.has(c.id)) : GOLDEN_CASES
  const saved = sample.reduce((s,c)=>s+Math.max(0,c.baseline_seconds-c.review_seconds),0)/60
  const followups = sample.reduce((s,c)=>s+c.avoided_followups,0)
  $('metricCases').textContent = String(reviewed || GOLDEN_CASES.length)
  $('metricSaved').textContent = `${Math.round(saved)} min`
  $('metricFollowups').textContent = String(followups)
  $('metricUseful').textContent = reviewed ? `${Math.round((useful/reviewed)*100)}%` : '—'
  $('metricActions').textContent = '0'
}

const meetingSteps = [
  ['1 · Mandant', 'Öffne zuerst die Vietnamese-first Mandantensicht: Anforderungen verstehen, fehlende Dokumente direkt ergänzen.'],
  ['2 · Intake-Team', 'Zeige die Queue: TrustReady bündelt unvollständige Fälle, Widersprüche und fertige Vorgänge.'],
  ['3 · Ein Fall', 'Öffne einen Fall und zeige VI-Original + DE-Arbeitsübersetzung + konkrete Quelle.'],
  ['4 · Entscheidung', 'Zeige den klaren nächsten Schritt. Team bereitet vor; Bao entscheidet fachlich.'],
  ['5 · Nachweis', 'Öffne die Timeline: jeder relevante Schritt ist nachvollziehbar, nicht nur ein AI-Ergebnis.'],
  ['6 · Nutzen', 'Zeige die Rehearsal-KPIs. Im echten 5-Tage-Pilot werden dieselben Kennzahlen aus realen Reviews gemessen.'],
  ['7 · Sicherheitsgrenze', 'Zeige: „Freigeben & senden“ bleibt deaktiviert. Human-approved execution ist ein separater späterer Release.']
]
function renderMeeting(){
  const [title,text] = meetingSteps[meetingStep]
  $('meetingTitle').textContent = title
  $('meetingText').textContent = text
  $('meetingCount').textContent = `${meetingStep+1}/${meetingSteps.length}`
}

function renderAll(){ renderFilters(); renderQueue(); renderDetail(); renderMetrics(); renderMeeting() }

document.querySelectorAll('[data-filter]').forEach(btn=>btn.addEventListener('click',()=>{activeFilter=btn.dataset.filter;renderAll()}))
$('meetingNext').addEventListener('click',()=>{meetingStep=(meetingStep+1)%meetingSteps.length;renderMeeting()})
$('meetingPrev').addEventListener('click',()=>{meetingStep=(meetingStep-1+meetingSteps.length)%meetingSteps.length;renderMeeting()})
$('meetingStart').addEventListener('click',()=>{$('meetingPanel').classList.add('show');meetingStep=0;renderMeeting()})
$('meetingClose').addEventListener('click',()=>$('meetingPanel').classList.remove('show'))
renderAll()
