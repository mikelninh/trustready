import assert from 'node:assert/strict'
import test from 'node:test'

function decision(classification,score){
  if(classification==='PROOF_GAP' && score>=75) return 'HUMAN_REVIEW_FOR_OUTREACH'
  if(['PROOF_GAP','REVIEW_SIGNAL'].includes(classification) && score>=55) return 'RESEARCH_MORE'
  return 'DO_NOT_OUTREACH'
}

test('only high-confidence proof gap can enter outreach review',()=>{
  assert.equal(decision('PROOF_GAP',80),'HUMAN_REVIEW_FOR_OUTREACH')
  assert.notEqual(decision('REVIEW_SIGNAL',95),'HUMAN_REVIEW_FOR_OUTREACH')
})

test('low commercial score never reaches outreach queue',()=>{
  assert.equal(decision('PROOF_GAP',60),'RESEARCH_MORE')
  assert.equal(decision('ARCHITECTURE_UNCERTAIN',100),'DO_NOT_OUTREACH')
})
