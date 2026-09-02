import test from 'node:test'
import assert from 'node:assert/strict'
import {createPostgresReplayStore,POSTGRES_REPLAY_STORE_DDL} from './legal-replay-store.mjs'

test('DDL enforces unique capability and nonce claims',()=>{assert.match(POSTGRES_REPLAY_STORE_DDL,/capability_id TEXT PRIMARY KEY/);assert.match(POSTGRES_REPLAY_STORE_DDL,/nonce_hash TEXT NOT NULL UNIQUE/)})
test('PostgreSQL adapter uses INSERT ON CONFLICT and never stores raw nonce',async()=>{const seen=new Set(),calls=[];const query=async(sql,params)=>{calls.push({sql,params});if(sql.startsWith('INSERT')){const key=`${params[0]}:${params[1]}`;if(seen.has(key))return{rowCount:0};seen.add(key);return{rowCount:1}}return{rowCount:0}};const store=createPostgresReplayStore({query}),args={idempotency_key:'cap-1',nonce:'a'.repeat(64),expires_at:'2026-09-02T13:00:00Z'};assert.equal(await store.claim(args),true);assert.equal(await store.claim(args),false);assert.match(calls[0].sql,/ON CONFLICT DO NOTHING/);assert.notEqual(calls[0].params[1],args.nonce);assert.match(calls[0].params[1],/^sha256:/)})
test('backend failure fails closed',async()=>{const store=createPostgresReplayStore({query:async()=>{throw new Error('db down')}});assert.equal(await store.claim({idempotency_key:'cap-1',nonce:'b'.repeat(64),expires_at:'2026-09-02T13:00:00Z'}),false)})
