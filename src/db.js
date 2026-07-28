const { Pool } = require("pg");
require("dotenv").config();

// Render's Postgres REQUIRES an encrypted (SSL) connection.
// Locally, if YOUR Postgres has no SSL, put DB_SSL=false in your local .env
// (do NOT set DB_SSL on Render).
const ssl = process.env.DB_SSL === "false" ? false : { rejectUnauthorized: false };

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
    })
  : new Pool({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      ssl,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
    });

pool.on("connect", () => console.log("✅ PostgreSQL connected — onebrain"));
pool.on("error", (err) => console.error("⚠️ Postgres pool error (kept alive):", err.message));

module.exports = pool;