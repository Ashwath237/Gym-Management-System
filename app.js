require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const app = express();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.SECRET_KEY;

const pool = new Pool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME
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

//Classes id Block
    app.get("/api/classes/:id", JwtVerify, (req,res,next)=>{
        const {id} = req.params
        const query  = `SELECT * FROM classes WHERE id = $1 `;
        pool.query(query, [id],(err,result)=>{
            if (err){
                const error = new Error('Failed to fetch Classes ');
                error.status = 500;
                next(error);
            }
            
            if(result.rows.length === 0){
                const error= new Error('Class not found');
                error.status = 404;
                return next(error);
            }
            
            res.json(result.rows[0]);
        })
    });

//Update Classes block
    app.put('/api/classes/:id', JwtVerify, (req, res, next) => {
        const { name, trainer_id, time, capacity, difficulty_level } = req.body;
        const query  = `UPDATE classes SET name = $1, trainer_id = $2, time = $3, capacity = $4, difficulty_level= $5 WHERE id = $6 `;
        const { id } = req.params;
        
        pool.query(query, [ name, trainer_id, time, capacity, difficulty_level, id],(err,result)=>{
            if (err){
                const error = new Error('Failed to name, trainer_id, time, capacity, difficulty_level');
                error.status = 500;
                return next(error);
            }
            res.json({ message: 'Classes updated successfully' });
        })
    });

//Create New classes
    app.post("/api/classes", JwtVerify, (req, res, next)=>{
    const query = `INSERT INTO classes ( name, trainer_id, time, capacity, difficulty_level ) VALUES ($1, $2, $3, $4, $5)`;
    const { name, trainer_id, time, capacity, difficulty_level } = req.body;
        
        pool.query(query, [ name ,trainer_id, time, capacity, difficulty_level], (err, result) => {
            if (err){
                const error = new Error('Failed to create new Class');
                error.status = 402;
                return next (error);
            }
            else {
                res.status(200).json({message: 'Class created successfully'});
            }
    });
});

//Delete Class
    app.delete('/api/classes/:id', JwtVerify, (req, res, next) => {
        const { id } = req.params;
        const query  = `DELETE FROM classes WHERE id = $1`;
        
        pool.query(query, [id],(err,result)=>{
            if (err){
                const error = new Error('Failed to Delete the Class');
                error.status = 500;
                return next(error);
            }
            res.json({ message: 'Class removed successfully' });
        })
    });


//Bookings Block
    app.get("/api/bookings", JwtVerify, (req, res, next) => {
        pool.query('SELECT * FROM bookings', (err, result) => {
            if (err) {
                const error = new Error( 'Failed to fetch Bookings' );
                error.status = 400;
                next(error);
            } 
            else {
                res.status(200).json({ bookings: result.rows });
            }
        });
    });

//New Bookings Block
    app.post("/api/bookings", JwtVerify, (req, res, next) => {
        
        const {  member_id, class_id, booked_date} = req.body;
        
        const query = 'INSERT INTO bookings (member_id, class_id, booked_date, status) VALUES ($1, $2, $3, $4)';
        
        pool.query(query, [member_id, class_id, booked_date, 'confirmed'], (err, result) => {
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

//Bookings id Block
    app.get("/api/bookings/:id", JwtVerify, (req,res,next)=>{
        const {id} = req.params
        const query  = `SELECT * FROM bookings WHERE id = $1 `;
        pool.query(query, [id],(err,result)=>{
            if (err){
                const error = new Error('Failed to fetch bookings info');
                error.status = 500;
                next(error);
            }
            
            if(result.rows.length === 0){
                const error= new Error('Bookings not found');
                error.status = 404;
                return next(error);
            }
            
            res.json(result.rows[0]);
        })
    });

//Update Bookings
    app.put('/api/bookings/:id', JwtVerify, (req, res, next) => {
        const { member_id, class_id, booked_date } = req.body;
        const query  = `UPDATE bookings SET member_id = $1, class_id = $2, booked_date = $3 WHERE id = $4`;
        const { id } = req.params;
        
        pool.query(query, [member_id, class_id, booked_date, id],(err,result)=>{
            if (err){
                const error = new Error('Failed to fetch member_id, class_id, booked_date');
                error.status = 500;
                return next(error);
            }
            res.json({ message: 'Bookings updated successfully' });
        })
    });

//Delete Bookings
    app.delete('/api/bookings/:id', JwtVerify, (req, res, next) => {
        const { id } = req.params;
        const query  = `DELETE FROM bookings WHERE id = $1`;
        
        pool.query(query, [id],(err,result)=>{
            if (err){
                const error = new Error('Failed to Delete the booking');
                error.status = 500;
                return next(error);
            }
            res.json({ message: 'Bookings removed successfully' });
        })
    });



//Members Block
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

//Create new members
    app.post("/api/members", JwtVerify, (req, res, next)=>{
        const query = `INSERT INTO members (user_id, age, fitness_level) VALUES ($1, $2, $3)`;
        const {user_id, age, fitness_level } = req.body;
        pool.query(query, [user_id, age, fitness_level], (err, result) => {
            if (err){
                const error = new Error('Failed to create new member');
                error.status = 402;
                return next (error);
            }
            else {
                res.status(200).json({message: 'Member created successfully'});
            }
    });
});


//Member id block
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
    
//Member Update Block
    app.put('/api/members/:id', JwtVerify, (req, res, next) => {
        const { age, fitness_level } = req.body;
        const query  = `UPDATE members SET age = $1, fitness_level = $2 WHERE id = $3`;
        const { id } = req.params;
        
        pool.query(query, [age, fitness_level, id],(err,result)=>{
            if (err){
                const error = new Error('Failed to fetch age, fitness level');
                error.status = 500;
                return next(error);
            }
            res.json({ message: 'Member updated successfully' });
        })
    });

//Member Delete Block
    app.delete('/api/members/:id', JwtVerify, (req, res, next) => {
        const { id } = req.params;
        const query  = `DELETE FROM members WHERE id = $1`;
        
        pool.query(query, [id],(err,result)=>{
            if (err){
                const error = new Error('Failed to Delete the User');
                error.status = 500;
                return next(error);
            }
            res.json({ message: 'Member removed successfully' });
        })
    });


//Trainers block

    app.get('/api/trainers', JwtVerify, (req,res,next)=>{
        const query = 'SELECT * FROM trainers';
        
        pool.query(query,(err,result)=>{
            if (err){
            const error = new Error('Failed to fetch trainers');
            error.status = 500;
            return next (error);
        }
        
        res.json({trainers: result.rows})
    });
    });

//Trainers id Block
    app.get("/api/trainers/:id", JwtVerify, (req,res,next)=>{
        const {id} = req.params
        const query  = `SELECT * FROM trainers WHERE id = $1 `;
        pool.query(query, [id],(err,result)=>{
            if (err){
                const error = new Error('Failed to fetch Trainers info');
                error.status = 500;
                next(error);
            }
            
            if(result.rows.length === 0){
                const error= new Error('Trainer not found');
                error.status = 404;
                return next(error);
            }
            
            res.json(result.rows[0]);
        })
    });

//Create New Trainers
    app.post("/api/trainers", JwtVerify, (req, res, next)=>{
        const query = `INSERT INTO trainers ( name, specialization, availability ) VALUES ($1, $2, $3)`;
        const { name, specialization, availability } = req.body;
        
        pool.query(query, [ name, specialization, availability], (err, result) => {
            if (err){
                const error = new Error('Failed to create new trainers');
                error.status = 402;
                return next (error);
            }
            else {
                res.status(200).json({message: 'trainers created successfully'});
            }
    });
});

//Update Trainer
    app.put('/api/trainers/:id', JwtVerify, (req, res, next) => {
        const { name, specialization, availability } = req.body;
        const query  = `UPDATE trainers SET name = $1, specialization = $2, availability = $3 WHERE id = $4`;
        const { id } = req.params;
        
        pool.query(query, [name, specialization, availability, id],(err,result)=>{
            if (err){
                const error = new Error('Failed to fetch name, specialization, availability');
                error.status = 500;
                return next(error);
            }
            res.json({ message: 'Trainer updated successfully' });
        })
    });

//Delete Trainer
    app.delete('/api/trainers/:id', JwtVerify, (req, res, next) => {
        const { id } = req.params;
        const query  = `DELETE FROM trainers WHERE id = $1`;
        
        pool.query(query, [id],(err,result)=>{
            if (err){
                const error = new Error('Failed to Delete the trainer');
                error.status = 500;
                return next(error);
            }
            res.json({ message: 'Trainer removed successfully' });
        })
    });

//Attendance Block
    app.get("/api/attendance", JwtVerify, (req, res, next) => {
        pool.query('SELECT * FROM attendance', (err, result) => {
            if (err) {
                const error = new Error( 'Failed to fetch attendance' );
                error.status = 400;
                next(error);
            } 
            else {
                res.status(200).json({ attendance: result.rows });
            }
        });
    });

//New attendance Block
    app.post("/api/attendance", JwtVerify, (req, res, next) => {
        
        const {  member_id, class_id, attended_date, check_in_time} = req.body;
        
        const query = 'INSERT INTO attendance (member_id, class_id, attended_date, check_in_time) VALUES ($1, $2, $3, $4)';
        
        pool.query(query, [member_id, class_id, attended_date, check_in_time], (err, result) => {
            if (err) {
                const error = new Error('Attendance failed')
                error.status = 400;
                next (error);
            } 
            else {
                res.status(200).json({message: 'Attendance created successfully'});
            }
        });
    });

//Attendance id Block
    app.get("/api/attendance/:id", JwtVerify, (req,res,next)=>{
        const {id} = req.params
        const query  = `SELECT * FROM attendance WHERE id = $1 `;
        pool.query(query, [id],(err,result)=>{
            if (err){
                const error = new Error('Failed to fetch attendance info');
                error.status = 500;
                next(error);
            }
            
            if(result.rows.length === 0){
                const error= new Error('Attendance not found');
                error.status = 404;
                return next(error);
            }
            
            res.json(result.rows[0]);
        })
    });

//Update attendance
    app.put('/api/attendance/:id', JwtVerify, (req, res, next) => {
        const { member_id, class_id, attended_date, check_in_time } = req.body;
        const query  = `UPDATE attendance SET member_id = $1, class_id = $2, attended_date = $3, check_in_time = $4 WHERE id = $5`;
        const { id } = req.params;
        
        pool.query(query, [member_id, class_id, attended_date, check_in_time, id],(err,result)=>{
            if (err){
                const error = new Error('Failed to fetch member_id, class_id, attended_date, check_in_time');
                error.status = 500;
                return next(error);
            }
            res.json({ message: 'Attendance updated successfully' });
        })
    });

//Delete attendance
    app.delete('/api/attendance/:id', JwtVerify, (req, res, next) => {
        const { id } = req.params;
        const query  = `DELETE FROM attendance WHERE id = $1`;
        
        pool.query(query, [id],(err,result)=>{
            if (err){
                const error = new Error('Failed to Delete the attendance');
                error.status = 500;
                return next(error);
            }
            res.json({ message: 'attendance removed successfully' });
        })
    });


    app.use(errorMiddleware);

    app.listen(3000, () => console.log("Server running on port 3000"));