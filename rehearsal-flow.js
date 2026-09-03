export const REHEARSAL_STATES = Object.freeze(['INCOMPLETE', 'REVIEW', 'READY', 'DONE'])

export function allowedRehearsalActions({ state, request_prepared = false, review_completed = false } = {}) {
  if (!REHEARSAL_STATES.includes(state)) throw new TypeError('known rehearsal state required')
  if (state === 'INCOMPLETE') {
    return Object.freeze(request_prepared
      ? ['simulate_client_completion']
      : ['request_missing'])
  }
  if (state === 'REVIEW') {
    return Object.freeze(review_completed
      ? ['submit_for_approval', 'mark_correction_needed']
      : ['review_sources'])
  }
  if (state === 'READY') return Object.freeze(['lawyer_approve', 'mark_correction_needed', 'lawyer_reject'])
  return Object.freeze(['view_result'])
}

export function applyRehearsalAction(snapshot, action) {
  const current = {
    state: snapshot?.state,
    request_prepared: snapshot?.request_prepared === true,
    review_completed: snapshot?.review_completed === true,
    outcome: snapshot?.outcome || null,
  }
  const allowed = allowedRehearsalActions(current)
  if (!allowed.includes(action)) throw new Error(`action ${action} denied for rehearsal state ${current.state}`)

  if (action === 'request_missing') return Object.freeze({ ...current, request_prepared: true })
  if (action === 'simulate_client_completion') return Object.freeze({ state: 'REVIEW', request_prepared: false, review_completed: false, outcome: null })
  if (action === 'review_sources') return Object.freeze({ ...current, review_completed: true })
  if (action === 'submit_for_approval') return Object.freeze({ state: 'READY', request_prepared: false, review_completed: true, outcome: null })
  if (action === 'mark_correction_needed') return Object.freeze({ state: 'REVIEW', request_prepared: false, review_completed: false, outcome: 'edited' })
  if (action === 'lawyer_approve') return Object.freeze({ state: 'DONE', request_prepared: false, review_completed: true, outcome: 'accepted' })
  if (action === 'lawyer_reject') return Object.freeze({ state: 'DONE', request_prepared: false, review_completed: true, outcome: 'rejected' })
  return Object.freeze(current)
}

export function simulateGoldenCaseToDecision(initialState) {
  let snapshot = { state: initialState, request_prepared: false, review_completed: false, outcome: null }
  const trace = []
  if (snapshot.state === 'INCOMPLETE') {
    snapshot = applyRehearsalAction(snapshot, 'request_missing'); trace.push('request_missing')
    snapshot = applyRehearsalAction(snapshot, 'simulate_client_completion'); trace.push('simulate_client_completion')
  }
  if (snapshot.state === 'REVIEW') {
    snapshot = applyRehearsalAction(snapshot, 'review_sources'); trace.push('review_sources')
    snapshot = applyRehearsalAction(snapshot, 'submit_for_approval'); trace.push('submit_for_approval')
  }
  if (snapshot.state === 'READY') {
    snapshot = applyRehearsalAction(snapshot, 'lawyer_approve'); trace.push('lawyer_approve')
  }
  return Object.freeze({ snapshot, trace: Object.freeze(trace) })
}
