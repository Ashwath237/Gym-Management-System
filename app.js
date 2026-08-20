    const express = require('express');
    const { Pool } = require('pg');
    const app = express();
    const bcrypt = require('bcryptjs');
    const jwt = require('jsonwebtoken');
    const SECRET_KEY = 'your_secret_key_here';

    const pool = new Pool({
        user: 'postgres',
        password: 'jotaro',
        host: 'localhost',
        port: 5432,
        database: 'gym_management'
    });

    app.use(express.json());

// Register Block
    app.post("/api/auth/register", async (req, res) => {
        const { username, email, password } = req.body;
        
        // Hash the password
        const hashedPassword= await bcrypt.hash(password,10);

        const query = 'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)';
        
        pool.query(query, [username, email, hashedPassword], (err, result) => {
            if (err) {
                res.status(400).json({ error: 'Registration failed', details: err.message });
            } 
            else {
                res.status(201).json({ message: 'User registered successfully', userId: result.rows[0]?.id });
            }
        });
    });

// Login Block
    app.post("/api/auth/login", (req, res) => {
        const { username, password } = req.body;
        
        const query = 'SELECT * FROM users WHERE username = $1';
        
        
        pool.query(query, [username], (err, result) => {
            console.log('Query error:', err);
            console.log('Query result:', result);
            
            if (err) {
                res.status(400).json({ error: 'Login failed' });
            } 
            else if (result.rows.length === 0) {
                res.status(401).json({ error: 'Invalid credentials' });
            } 
            else {
                console.log('Password from request:', req.body.password);
                console.log('Hash from database:', result.rows[0].password_hash);
                
                bcrypt.compare(req.body.password,result.rows[0].password_hash).then(isMatch =>{
                    if (isMatch) {  
                        const token = jwt.sign({ userId: result.rows[0].id }, SECRET_KEY, { expiresIn: '1h' });
                        res.status(200).json({ message: 'Login successful', token: token });
                    }
                    
                    else {
                        res.status(401).json({ message: 'Invalid credentials' });
                    }
                });
            }
        
        });
    });

//classes block
    app.get("/api/classes", (req, res) => {
        pool.query('SELECT * FROM classes', (err, result) => {
            if (err) {
                res.status(400).json({ error: 'Failed to fetch classes' });
            } 
            else {
                res.status(200).json({ classes: result.rows });
            }
        });
    });

//Bookings Block
    app.post("/api/bookings", (req, res) => {
        
        const {  member_id, class_id } = req.body;
        
        const query = 'INSERT INTO bookings (member_id, class_id, status) VALUES ($1, $2, $3)';
        
        pool.query(query, [member_id, class_id, 'confirmed'], (err, result) => {
            if (err) {
                res.status(400).json({ error: 'Booking failed' });
            } 
            else {
                res.status(201).json({ message: 'Booking created', bookingId: result.rows[0]?.id });
            }
        });
    });

    app.listen(3000, () => console.log("Server running on port 3000"));