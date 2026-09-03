import { GOLDEN_CASES } from './golden-cases.js'
import { allowedRehearsalActions, applyRehearsalAction } from './rehearsal-flow.js'

const stateLabels = { INCOMPLETE: 'Unvollständig', REVIEW: 'Prüfen', READY: 'Zur Freigabe', DONE: 'Erledigt' }
const NOTE_KEY = 'trustready-bao-rehearsal-notes-v1'
let selectedId = GOLDEN_CASES[0].id
let activeFilter = 'ALL'
let meetingStep = 0
const snapshots = new Map(GOLDEN_CASES.map(c => [c.id, { state: c.state, request_prepared: false, review_completed: false, outcome: null }]))
const messages = new Map()
const notes = loadNotes()

const $ = (id) => document.getElementById(id)
const esc = (v='') => String(v).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))

function loadNotes(){
  try {
    const parsed = JSON.parse(localStorage.getItem(NOTE_KEY) || '{}')
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {}
  } catch { return {} }
}

function saveNotes(){
  localStorage.setItem(NOTE_KEY, JSON.stringify(notes))
}

function filteredCases(){
  return GOLDEN_CASES.filter(c => activeFilter === 'ALL' || snapshots.get(c.id).state === activeFilter)
}

function renderQueue(){
  const list = $('caseList')
  list.innerHTML = filteredCases().map(c => {
    const st = snapshots.get(c.id).state
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
    const count = f==='ALL' ? GOLDEN_CASES.length : [...snapshots.values()].filter(v=>v.state===f).length
    btn.textContent = `${f==='ALL'?'Alle':stateLabels[f]} · ${count}`
    btn.classList.toggle('active', activeFilter===f)
  })
}

function currentCase(){ return GOLDEN_CASES.find(c => c.id === selectedId) }

function reviewButtonLabel(c){
  if (c.id === 'TR-GOLD-003') return 'Schreiben & Aktennotiz vergleichen'
  if (c.id === 'TR-GOLD-005') return 'Pass & Vertrag vergleichen'
  if (c.id === 'TR-GOLD-009') return 'Vertrag v1 & v2 vergleichen'
  if (c.id === 'TR-GOLD-011') return 'Sonderfall manuell sichten'
  return 'Vorgang jetzt prüfen'
}

function renderDetail(){
  const c = currentCase(); if(!c) return
  const snapshot = snapshots.get(c.id)
  $('detailTitle').textContent = c.title
  $('detailMeta').textContent = `${c.client_label} · ${c.category} · ${stateLabels[snapshot.state]}`
  $('vnOriginal').textContent = c.vn_original
  $('deTranslation').textContent = c.de_translation
  $('summary').textContent = c.summary
  $('nextAction').textContent = suggestionFor(c, snapshot)
  $('openPoints').innerHTML = c.open_points.length ? c.open_points.map(x=>`<li>${esc(x)}</li>`).join('') : '<li class="goodText">Keine offenen Punkte.</li>'
  $('documents').innerHTML = c.documents.length ? c.documents.map(([n,s])=>`<div class="docRow"><span>${esc(n)}</span><b>${esc(s)}</b></div>`).join('') : '<div class="docRow"><span>Keine Dokumente im synthetischen Fall</span><b>—</b></div>'
  $('timeline').innerHTML = c.timeline.map((x,i)=>`<div class="timelineItem"><span>${i+1}</span><p>${esc(x)}</p></div>`).join('')
  renderActions(c, snapshot)
  renderNote(c)
}

function suggestionFor(c, snapshot){
  if (snapshot.state === 'INCOMPLETE' && snapshot.request_prepared) return 'Mandant ergänzt die fehlenden Unterlagen. Danach prüft das Team den Vorgang erneut.'
  if (snapshot.state === 'REVIEW' && snapshot.review_completed) return 'Prüfung ist abgeschlossen. Wenn alles stimmt, den Vorgang jetzt Bao zur Freigabe vorlegen.'
  if (snapshot.state === 'READY') return 'Bao prüft den vorbereiteten Vorgang und entscheidet fachlich: freigeben, korrigieren oder ablehnen.'
  if (snapshot.state === 'DONE') return snapshot.outcome === 'accepted' ? 'Vorgang ist fachlich freigegeben. Im Shadow Pilot endet der Ablauf hier.' : 'Entscheidung ist dokumentiert. Es wurde nichts extern ausgeführt.'
  return c.next_action
}

function renderActions(c, snapshot){
  const box = $('actions')
  const allowed = allowedRehearsalActions(snapshot)
  const labels = {
    request_missing: 'Fehlende Unterlagen / Angaben anfordern',
    simulate_client_completion: 'Eingang der Ergänzung simulieren',
    review_sources: reviewButtonLabel(c),
    submit_for_approval: 'Prüfung abgeschlossen → Bao vorlegen',
    mark_correction_needed: 'Korrektur nötig → zurück zur Prüfung',
    lawyer_approve: 'Vorgang fachlich freigeben',
    lawyer_reject: 'Vorgang ablehnen',
    view_result: 'Ergebnis ansehen'
  }
  box.innerHTML = allowed.map((action,i)=>`<button data-action="${action}" class="${i===0?'primary':''} ${action==='lawyer_reject'?'danger':''}">${labels[action]}</button>`).join('') + `<button disabled>Freigeben & senden — späterer Release</button>`
  box.querySelectorAll('[data-action]').forEach(btn=>btn.addEventListener('click',()=>handleAction(btn.dataset.action,c)))

  const review = $('reviewPanel')
  if (snapshot.review_completed) {
    review.innerHTML = `<b>Prüfansicht abgeschlossen</b>${c.documents.length ? c.documents.map(([n,s])=>`<div class="reviewRow"><span>${esc(n)}</span><strong>${esc(s)}</strong></div>`).join('') : '<div class="reviewRow"><span>Quellen geprüft</span><strong>manuell</strong></div>'}<div style="margin-top:8px">Nächster Schritt: <strong>„Prüfung abgeschlossen → Bao vorlegen“</strong> oder Korrektur zurück in die Prüfung.</div>`
    review.classList.add('show')
  } else {
    review.classList.remove('show'); review.innerHTML = ''
  }

  const result = $('actionResult')
  const message = messages.get(c.id)
  if (message) { result.innerHTML = message; result.classList.add('show') }
  else { result.classList.remove('show'); result.innerHTML = '' }
}

function handleAction(action,c){
  const current = snapshots.get(c.id)
  if (action === 'view_result') {
    messages.set(c.id, 'Ergebnis ist dokumentiert. Kein externer Schritt wurde ausgeführt.')
    renderAll(); return
  }
  const next = applyRehearsalAction(current, action)
  snapshots.set(c.id, next)

  if(action==='request_missing') messages.set(c.id, 'Rückfrage ist <b>lokal vorbereitet</b> (VI-first). Im Rehearsal wird nichts versendet. Als Nächstes ergänzt der Mandant die fehlenden Angaben.')
  if(action==='simulate_client_completion') messages.set(c.id, 'Ergänzung ist <b>synthetisch eingegangen</b>. Der Vorgang steht jetzt auf „Prüfen“. Als Nächstes werden Quellen und Formalien kontrolliert.')
  if(action==='review_sources') messages.set(c.id, 'Die relevanten Quellen sind jetzt in der Prüfansicht sichtbar. <b>Erst nach dieser Prüfung</b> kann der Vorgang Bao vorgelegt werden.')
  if(action==='submit_for_approval') messages.set(c.id, 'Prüfung abgeschlossen. Der Vorgang liegt jetzt <b>bei Bao zur fachlichen Entscheidung</b>.')
  if(action==='mark_correction_needed') messages.set(c.id, 'Korrektur ist markiert. Der Vorgang geht <b>zurück in die Prüfung</b>; es wurde nichts extern ausgeführt.')
  if(action==='lawyer_approve') messages.set(c.id, 'Fachlich freigegeben. <b>Shadow Pilot endet hier</b> — kein Versand.')
  if(action==='lawyer_reject') messages.set(c.id, 'Vorgang abgelehnt. Kein externer Schritt wurde ausgeführt.')
  renderAll()
}

function renderMetrics(){
  const decided = [...snapshots.entries()].filter(([,s])=>s.outcome).map(([id])=>id)
  const accepted = [...snapshots.values()].filter(s=>s.outcome==='accepted').length
  const edited = [...snapshots.values()].filter(s=>s.outcome==='edited').length
  const sample = decided.length ? GOLDEN_CASES.filter(c=>decided.includes(c.id)) : GOLDEN_CASES
  const saved = sample.reduce((s,c)=>s+Math.max(0,c.baseline_seconds-c.review_seconds),0)/60
  const followups = sample.reduce((s,c)=>s+c.avoided_followups,0)
  $('metricCases').textContent = String(decided.length || GOLDEN_CASES.length)
  $('metricSaved').textContent = `${Math.round(saved)} min`
  $('metricFollowups').textContent = String(followups)
  $('metricUseful').textContent = decided.length ? `${Math.round(((accepted+edited)/decided.length)*100)}%` : '—'
  $('metricActions').textContent = '0'
}

function renderNote(c){
  const area = $('caseNote')
  area.value = notes[c.id]?.note || ''
  $('noteStatus').textContent = notes[c.id]?.note ? 'Lokal gespeichert · nur Produkt-/Workflow-Feedback.' : 'Lokal im Browser gespeichert · keine Mandatsdaten eintragen.'
}

function saveCurrentNote(){
  const c = currentCase(); if(!c) return
  const note = $('caseNote').value.trim()
  if (note) notes[c.id] = { note, updated_at: new Date().toISOString() }
  else delete notes[c.id]
  saveNotes()
  $('noteStatus').textContent = note ? 'Gespeichert · bereit fürs Feedback-Paket.' : 'Notiz entfernt.'
}

function exportFeedback(){
  const payload = {
    schema: 'trustready-bao-rehearsal-feedback-v1',
    generated_at: new Date().toISOString(),
    warning: 'Workflow/Product feedback only. No real mandate data.',
    notes: Object.entries(notes).filter(([,v])=>v?.note).map(([case_id,v])=>({ case_id, note: v.note, updated_at: v.updated_at }))
  }
  const href = `data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(payload,null,2))}`
  const link = document.createElement('a')
  link.href = href
  link.download = 'trustready-bao-feedback.json'
  link.click()
  $('noteStatus').textContent = `Feedback-Paket erstellt · ${payload.notes.length} Notiz(en).`
}

const meetingSteps = [
  ['1 · Mandant', 'Starte mit der Vietnamese-first Mandantensicht: Was fehlt, was kann direkt ergänzt werden?'],
  ['2 · Vorgänge', 'Klappe „Heutige Vorgänge“ nur auf, wenn du die Queue zeigen willst. Sonst bleibt der Fokus auf einem Fall.'],
  ['3 · Ein Fall', 'Zeige nur Original, Arbeitsübersetzung und TrustReady-Vorschlag. Details sind einklappbar.'],
  ['4 · Prüfung', 'Klicke die konkrete Prüfaktion. Erst danach erscheint „Prüfung abgeschlossen → Bao vorlegen“.'],
  ['5 · Bao entscheidet', 'Bao sieht einen vorbereiteten Vorgang und wählt: freigeben, Korrektur oder ablehnen.'],
  ['6 · Feedback', 'Bei jedem Fall können wir Produkt-/Workflow-Feedback notieren. Es wird lokal gespeichert und als JSON exportiert.'],
  ['7 · Sicherheitsgrenze', '„Freigeben & senden“ bleibt deaktiviert. Human-approved execution ist ein separater späterer Release.']
]
function renderMeeting(){
  const [title,text] = meetingSteps[meetingStep]
  $('meetingTitle').textContent = title
  $('meetingText').textContent = text
  $('meetingCount').textContent = `${meetingStep+1}/${meetingSteps.length}`
}

function renderAll(){ renderFilters(); renderQueue(); renderDetail(); renderMetrics(); renderMeeting() }

document.querySelectorAll('[data-filter]').forEach(btn=>btn.addEventListener('click',()=>{activeFilter=btn.dataset.filter;renderAll()}))
$('queueToggle').addEventListener('click',()=>{
  const collapsed = $('shell').classList.toggle('queueCollapsed')
  $('queueToggle').textContent = collapsed ? 'Vorgänge anzeigen' : 'Einklappen'
  $('queueToggle').setAttribute('aria-expanded', String(!collapsed))
})
$('caseNote').addEventListener('input', saveCurrentNote)
$('exportNotes').addEventListener('click', exportFeedback)
$('meetingNext').addEventListener('click',()=>{meetingStep=(meetingStep+1)%meetingSteps.length;renderMeeting()})
$('meetingPrev').addEventListener('click',()=>{meetingStep=(meetingStep-1+meetingSteps.length)%meetingSteps.length;renderMeeting()})
$('meetingStart').addEventListener('click',()=>{$('meetingPanel').classList.add('show');meetingStep=0;renderMeeting()})
$('meetingClose').addEventListener('click',()=>$('meetingPanel').classList.remove('show'))
renderAll()
