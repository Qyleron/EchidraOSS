// dashboard/server.js
const express = require("express");
const app = express();
const PORT = 8080;

app.use(express.static("public"));

require('dotenv').config();

const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});


app.listen(PORT, () => {
  console.log(`Dashboard running at http://localhost:${PORT}`);
});
