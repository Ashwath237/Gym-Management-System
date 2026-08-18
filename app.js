const express = require('express');
const { Pool } = require('pg');
const app = express();

const pool = new Pool({
    user: 'postgres',
    password: 'jotaro',
    host: 'localhost',
    port: 5432,
    database: 'gym_management'
});

app.use(express.json());

app.post("/api/auth/register", (req,res)=>{
    const { username, email, password } = req.body;
    const query = 'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)';
    pool.query(query, [username, email, password], (err, result) => {
        if (err) {
            res.status(400).json({ error: 'Registration failed', details: err.message });
        } 
        else {
            res.status(201).json({ message: 'User registered successfully', userId: result.rows[0]?.id });
        }
});
});

    
app.post("/api/auth/login", (req,res)=>{
    const { username, password } = req.body;
    const query = 'SELECT * FROM users WHERE username = $1 AND password_hash = $2';
    pool.query(query, [username, password], (err, result) => {
        if (err) {
            res.status(400).json({ error: 'Login failed' });
        } 
        else if (result.rows.length === 0) {
            res.status(401).json({ error: 'Invalid credentials' });
        } 
        else {
            res.status(200).json({ message: 'Login successful', user: result.rows[0] });
    }
});
});
app.listen(3000, ()=>console.log("Server running on port 3000"))
