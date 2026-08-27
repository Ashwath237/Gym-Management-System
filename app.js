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
    app.post("/api/auth/register", async (req, res, next) => {
        const { username, email, password } = req.body;
        
        if (!username || username.length <3){
            const error = new Error('Username should at least contain 3 characters');
            error.status = 400;
            throw error;
            
        }

        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){
            const error = new Error('Enter Valid Email');
            error.status = 400;
            throw error;
        }

        if (!password || password.length < 8 ){
            const error = new Error('Password should have atleast 8 characters');
            error.status = 400;
            throw error;
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password,10);
        
        const query = 'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)';
        pool.query(query, [username, email, hashedPassword], (err, result) => {
            if (err) {
                const error = new Error('Registration failed');
                error.status = 400;
                next (error); 
            } 
            else {
                res.status(201).json({ message: 'User registered successfully', userId: result.rows[0]?.id });
            }
        });
    });

// Login Block
    app.post("/api/auth/login", (req, res, next) => {
        const { username, password } = req.body;
        
        const query = 'SELECT * FROM users WHERE username = $1';
        
        
        pool.query(query, [username], (err, result) => {
            console.log('Query error:', err);
            console.log('Query result:', result);
            
            if (err) {
                const error = new Error('Login Failed')
                error.status = 400;
                next (error);
            } 
            else if (result.rows.length === 0) {
                const error = new Error('Invalid credentials')
                error.status = 400;
                next (error);
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
                        const error = new Error('Invalid Credentials')
                        error.status = 400;
                        next (error);
                    }
                }).catch(err => {
                    const error = new Error ('Password comparison Failed')
                    error.status = 500;
                    next(error);
                });
            }
        
        });
    });

//session expiration middleware
    function JwtVerify(req,res,next){
        if(req.headers.authorization){
            const token = req.headers.authorization.split(" ")[1];
            try{    
                const decoded = jwt.verify(token,SECRET_KEY);
                req.user = decoded;
                next();
            }
            catch(err){
                const error = new Error('Invalid Token or Token expired');
                error.status = 401;
                next(error);
            }
        }
        else{
            res.status(401).json({ message:"No token provided " });
        }
    }

    function errorMiddleware(err, req, res, next) {
        console.log("Error:", err.message);
        console.log("Stack:", err.stack);
    res.status(err.status || 500).json({ error: err.message });
}

//classes block
    app.get("/api/classes", JwtVerify, (req, res, next) => {
        pool.query('SELECT * FROM classes', (err, result) => {
            if (err) {
                const error = new Error( 'Failed to fetch classes' );
                error.status = 400;
                next(error);
            } 
            else {
                res.status(200).json({ classes: result.rows });
            }
        });
    });

//Bookings Block
    app.post("/api/bookings", JwtVerify, (req, res, next) => {
        
        const {  member_id, class_id } = req.body;
        
        const query = 'INSERT INTO bookings (member_id, class_id, status) VALUES ($1, $2, $3)';
        
        pool.query(query, [member_id, class_id, 'confirmed'], (err, result) => {
            if (err) {
                const error = new Error('Booking failed')
                error.status = 400;
                next (error);
            } 
            else {
                res.status(201).json({ message: 'Booking created', bookingId: result.rows[0]?.id });
            }
        });
    });

    app.get("/api/members", JwtVerify, (req, res, next) => {
        pool.query('SELECT * FROM members ', (err, result) => {
            if(err){
                const error = new Error('Failed to fetch members');
                error.status = 400;
                next (error);
            }
            else{
                res.status(200).json({members:result.rows});
            }
        });
    });
    
    //member id block
    app.get("/api/members/:id", JwtVerify, (req,res,next)=>{
        const {id} = req.params
        const query  = `SELECT m.id, m.age, m.fitness_level, m.registration_date, u.username, u.email
                        FROM members m
                        JOIN users u ON m.user_id = u.id
                        WHERE m.id = $1`;
        
        pool.query(query, [id],(err,result)=>{
            if (err){
                const error = new Error('Failed to fetch member');
                error.status = 500;
                next(error);
            }
            if(result.rows.length === 0){
                const error= new Error('Member not found');
                error.status = 404;
                return next(error);
            }
            res.json(result.rows[0]);
        })
    });
    
    
    app.use(errorMiddleware);

    app.listen(3000, () => console.log("Server running on port 3000"));