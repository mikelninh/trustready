import {parseTime,sha256} from './legal-key-identity.mjs'

export const POSTGRES_REPLAY_STORE_DDL=`CREATE TABLE IF NOT EXISTS trustready_legal_action_nonce (
  capability_id TEXT PRIMARY KEY,
  nonce_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS trustready_legal_action_nonce_expiry_idx ON trustready_legal_action_nonce (expires_at);`

export function createPostgresReplayStore({query}){if(typeof query!=='function')throw new TypeError('PostgreSQL query function required');return{durable:true,atomic:true,backend:'postgres-primary-key-unique-claim',async claim({idempotency_key,nonce,expires_at}){if(!/^[A-Za-z0-9._:-]{1,128}$/.test(idempotency_key||'')||typeof nonce!=='string'||nonce.length<32)throw new TypeError('valid capability id and nonce required');if(parseTime(expires_at)<=Date.now()-24*60*60*1000)return false;const nonceHash=`sha256:${sha256(nonce)}`;try{const result=await query(`INSERT INTO trustready_legal_action_nonce (capability_id, nonce_hash, expires_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING capability_id`,[idempotency_key,nonceHash,expires_at]);return Number(result?.rowCount)===1}catch{return false}},async prune({before=new Date().toISOString()}={}){parseTime(before);try{const result=await query(`DELETE FROM trustready_legal_action_nonce WHERE expires_at < $1`,[before]);return Number(result?.rowCount)||0}catch{return 0}}}}
