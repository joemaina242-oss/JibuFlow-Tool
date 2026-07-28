const pool = require("./db");

async function getMemory(username) {
  const res = await pool.query(
    `SELECT fact_key, fact_value, confidence FROM memory_logs
     WHERE tiktok_username = $1 ORDER BY created_at DESC LIMIT 10`,
    [username]
  );
  return res.rows;
}

async function saveFact(username, key, value, confidence) {
  await pool.query(
    `INSERT INTO users (tiktok_username) VALUES ($1)
     ON CONFLICT (tiktok_username) DO UPDATE SET last_seen_at = NOW()`,
    [username]
  );
  await pool.query(
    `INSERT INTO memory_logs (tiktok_username, fact_key, fact_value, confidence)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (tiktok_username, fact_key)
     DO UPDATE SET fact_value = EXCLUDED.fact_value,
                   confidence = EXCLUDED.confidence,
                   updated_at = NOW()`,
    [username, key, value, confidence]
  );
}

// 5th arg `meta` tags the row with the owner account + post (dashboard math needs this)
async function logInteraction(username, comment, reply, intent, meta = {}) {
  await pool.query(
    `INSERT INTO interactions (tiktok_username, comment, reply, intent, account_id, post_id)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [username, comment, reply, intent, meta.accountId || null, meta.postId || null]
  );
}

module.exports = { getMemory, saveFact, logInteraction };