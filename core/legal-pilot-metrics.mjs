const CASE_HASH = /^sha256:[a-f0-9]{64}$/
const EVENT_ID = /^[A-Za-z0-9._:-]{8,128}$/
const ALLOWED_TYPES = new Set([
  'proposal_reviewed',
  'proposal_accepted',
  'proposal_edited',
  'proposal_rejected',
  'deadline_confirmed',
  'matter_assignment_confirmed',
  'blocked_action_attempt',
])

function finiteNonNegative(value, label) {
  const number = Number(value)
  if (!Number.isFinite(number) || number < 0) throw new TypeError(`${label} must be a finite non-negative number`)
  return number
}

function strictKeys(object, allowed, label) {
  if (!object || typeof object !== 'object' || Array.isArray(object) || Object.getPrototypeOf(object) !== Object.prototype) {
    throw new TypeError(`${label} must be a plain object`)
  }
  for (const key of Object.keys(object)) if (!allowed.has(key)) throw new TypeError(`${label}.${key} is not allowed`)
}

export function normalizePilotEvent(input) {
  strictKeys(input, new Set(['event_id', 'type', 'case_ref_hash', 'occurred_at', 'review_seconds', 'baseline_seconds', 'correct', 'reason_code']), 'event')
  if (!EVENT_ID.test(input.event_id || '')) throw new TypeError('valid event_id required')
  if (!ALLOWED_TYPES.has(input.type)) throw new TypeError('pilot event type denied')
  if (!CASE_HASH.test(input.case_ref_hash || '')) throw new TypeError('case_ref_hash must be a sha256 digest; raw matter identifiers are denied')
  const occurredAt = new Date(input.occurred_at)
  if (!Number.isFinite(occurredAt.getTime())) throw new TypeError('valid occurred_at required')

  const event = {
    event_id: input.event_id,
    type: input.type,
    case_ref_hash: input.case_ref_hash,
    occurred_at: occurredAt.toISOString(),
  }

  if (input.review_seconds !== undefined) event.review_seconds = finiteNonNegative(input.review_seconds, 'review_seconds')
  if (input.baseline_seconds !== undefined) event.baseline_seconds = finiteNonNegative(input.baseline_seconds, 'baseline_seconds')
  if (input.correct !== undefined) {
    if (typeof input.correct !== 'boolean') throw new TypeError('correct must be boolean')
    event.correct = input.correct
  }
  if (input.reason_code !== undefined) {
    if (!/^[A-Z0-9_:-]{2,64}$/.test(input.reason_code)) throw new TypeError('reason_code must be a bounded machine code')
    event.reason_code = input.reason_code
  }

  if (['proposal_accepted', 'proposal_edited', 'proposal_rejected'].includes(event.type)) {
    if (event.review_seconds === undefined || event.baseline_seconds === undefined) throw new TypeError('review and baseline duration required for proposal outcome')
  }
  if (['deadline_confirmed', 'matter_assignment_confirmed'].includes(event.type) && event.correct === undefined) {
    throw new TypeError('correctness result required for confirmation event')
  }

  return Object.freeze(event)
}

function median(numbers) {
  if (!numbers.length) return 0
  const values = [...numbers].sort((a, b) => a - b)
  const middle = Math.floor(values.length / 2)
  return values.length % 2 ? values[middle] : (values[middle - 1] + values[middle]) / 2
}

export function summarizePilotEvents(inputs = []) {
  if (!Array.isArray(inputs)) throw new TypeError('pilot events array required')
  const events = inputs.map(normalizePilotEvent)
  const ids = new Set()
  for (const event of events) {
    if (ids.has(event.event_id)) throw new Error('duplicate pilot event_id denied')
    ids.add(event.event_id)
  }

  const outcomes = events.filter((event) => ['proposal_accepted', 'proposal_edited', 'proposal_rejected'].includes(event.type))
  const accepted = outcomes.filter((event) => event.type === 'proposal_accepted').length
  const edited = outcomes.filter((event) => event.type === 'proposal_edited').length
  const rejected = outcomes.filter((event) => event.type === 'proposal_rejected').length
  const useful = accepted + edited
  const reviewSeconds = outcomes.map((event) => event.review_seconds)
  const savedSeconds = outcomes.reduce((total, event) => {
    if (!['proposal_accepted', 'proposal_edited'].includes(event.type)) return total
    return total + Math.max(0, event.baseline_seconds - event.review_seconds)
  }, 0)

  const deadlineEvents = events.filter((event) => event.type === 'deadline_confirmed')
  const matterEvents = events.filter((event) => event.type === 'matter_assignment_confirmed')
  const ratio = (rows) => rows.length ? rows.filter((row) => row.correct === true).length / rows.length : null

  return Object.freeze({
    schema: 'trustready-legal-pilot-metrics-v1',
    unique_cases: new Set(events.map((event) => event.case_ref_hash)).size,
    proposal_outcomes: outcomes.length,
    accepted,
    edited,
    rejected,
    useful_rate: outcomes.length ? useful / outcomes.length : null,
    total_saved_minutes: Math.round((savedSeconds / 60) * 10) / 10,
    median_review_seconds: Math.round(median(reviewSeconds) * 10) / 10,
    deadline_accuracy: ratio(deadlineEvents),
    matter_assignment_accuracy: ratio(matterEvents),
    blocked_action_attempts: events.filter((event) => event.type === 'blocked_action_attempt').length,
    autonomous_external_actions_executed: 0,
  })
}
