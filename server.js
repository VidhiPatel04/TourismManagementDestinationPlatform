const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const fs = require('fs');
require('dotenv').config();

const app = express();

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Cookie Parser
app.use(cookieParser());

// Session Middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax'
    }
}));

// CSRF Protection
const csrfProtection = csrf({ cookie: true });

// Database connection pool
const db = mysql.createPool({
    host: 'localhost',
    user: 'jay_patel',
    password: process.env.DB_PASSWORD || 'SecureAppPass456!',
    database: 'travel_explorer_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test the pool connection
db.getConnection((err, connection) => {
    if (err) {
        console.error('Error connecting to MySQL pool:', err.message);
        process.exit(1);
    }
    console.log('Successfully connected to MySQL database: travel_explorer_db');
    connection.release();
});

// Handle connection errors
db.on('error', (err) => {
    console.error('MySQL pool error:', err.message);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.log('Attempting to reconnect to MySQL...');
        // The pool will automatically attempt to reconnect
    } else {
        throw err;
    }
});

// Verify users table
db.query(`
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(255) NOT NULL,
        last_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        phone VARCHAR(20) NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
    if (err) {
        console.error('Error creating users table:', err.message);
        return;
    }
    console.log('Users table verified successfully');
});

// Insert test user with detailed logging
const testEmail = 'testuser@example.com';
const testPassword = 'password123';
const testFirstName = 'Test';
const testLastName = 'User';
const testPhone = '+1234567890';
bcrypt.hash(testPassword, 10, (err, hash) => {
    if (err) {
        console.error('Error hashing test user password:', err.message);
        return;
    }
    console.log('Hashed test user password:', hash);
    db.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting connection for test user:', err.message);
            return;
        }
        connection.query(
            'INSERT INTO users (first_name, last_name, email, phone, password) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE first_name=?, last_name=?, phone=?, password=?',
            [testFirstName, testLastName, testEmail, testPhone, hash, testFirstName, testLastName, testPhone, hash],
            (err, result) => {
                if (err) {
                    console.error('Error inserting test user:', err.message);
                    connection.release();
                    return;
                }
                console.log('Test user insertion result:', result);
                connection.query('SELECT * FROM users WHERE email = ?', [testEmail], (err, results) => {
                    if (err) {
                        console.error('Error verifying test user:', err.message);
                        connection.release();
                        return;
                    }
                    console.log('Test user in database:', results);
                    connection.release();
                });
            }
        );
    });
});

// Verify bookings table with updated schema
db.query(`
    CREATE TABLE IF NOT EXISTS bookings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        client_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        phone VARCHAR(20),
        destination VARCHAR(255) NOT NULL,
        departure_date DATE NOT NULL,
        return_date DATE,
        passengers INT NOT NULL,
        payment_method VARCHAR(50) NOT NULL,
        card_number VARCHAR(255) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        payment_status VARCHAR(50) NOT NULL,
        cardholder_name VARCHAR(255),
        expiry VARCHAR(10),
        cvv VARCHAR(255),
        street_address VARCHAR(255),
        city VARCHAR(100),
        state VARCHAR(100),
        zip_code VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`, (err) => {
    if (err) {
        console.error('Error creating bookings table:', err.message);
        return;
    }
    console.log('Bookings table verified successfully');
});

// Email setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'travelexplorer923@gmail.com',
        pass: process.env.EMAIL_PASS || 'zobr hfns rtze izji'
    }
});

// Function to generate PDF receipt
function generateReceiptPDF(bookingData, callback) {
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    const filePath = `./receipt_${bookingData.id}.pdf`;
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    doc.fontSize(20).text('Travel Explorer - Booking Receipt', { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text(`Booking ID: ${bookingData.id}`, { align: 'left' });
    doc.text(`Date: ${new Date().toLocaleDateString()}`, { align: 'left' });
    doc.moveDown();

    doc.fontSize(14).text('Booking Details', { underline: true });
    doc.moveDown(0.5);
    doc.fontSize(12).text(`Client Name: ${bookingData.client_name}`);
    doc.text(`Email: ${bookingData.email}`);
    doc.text(`Phone: ${bookingData.phone || 'Not provided'}`);
    doc.text(`Destination: ${bookingData.destination}`);
    doc.text(`Departure Date: ${bookingData.departure_date}`);
    doc.text(`Return Date: ${bookingData.return_date || 'Not provided'}`);
    doc.text(`Passengers: ${bookingData.passengers}`);
    doc.moveDown();

    doc.fontSize(14).text('Payment Details', { underline: true });
    doc.moveDown(0.5);
    doc.fontSize(12).text(`Payment Method: ${bookingData.payment_method}`);
    doc.text(`Card Number: ${bookingData.card_number.slice(-4).padStart(16, '*')}`);
    doc.text(`Amount: $${bookingData.amount}`);
    doc.text(`Payment Status: ${bookingData.payment_status}`);
    doc.moveDown();

    if (bookingData.street_address) {
        doc.fontSize(14).text('Billing Address', { underline: true });
        doc.moveDown(0.5);
        doc.fontSize(12).text(`${bookingData.street_address}`);
        doc.text(`${bookingData.city}, ${bookingData.state} ${bookingData.zip_code}`);
    }

    doc.moveDown();
    doc.fontSize(10).text('Thank you for choosing Travel Explorer!', { align: 'center' });

    doc.end();

    stream.on('finish', () => {
        console.log(`PDF generated at ${filePath}`);
        callback(filePath);
    });

    stream.on('error', (err) => {
        console.error('Error generating PDF:', err.message);
        callback(null);
    });
}

// Routes
app.get('/check-session', (req, res) => {
    console.log('Checking session:', req.sessionID, req.session);
    res.json({ isLoggedIn: !!req.session.user });
});

app.get('/get-csrf-token', csrfProtection, (req, res) => {
    try {
        if (!req.session.csrfToken) {
            req.session.csrfToken = req.csrfToken();
        }
        console.log('Serving CSRF token:', req.session.csrfToken, 'for session:', req.sessionID, req.session);
        res.json({ csrfToken: req.session.csrfToken });
    } catch (error) {
        console.error('Error in /get-csrf-token:', error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/signup', async (req, res) => {
    const { first_name, last_name, email, phone, password } = req.body;
    console.log('Signup attempt with email:', email);
    console.log('Request body:', req.body);
    if (!first_name || !last_name || !email || !phone || !password || typeof password !== 'string' || password.trim() === '') {
        console.log('Invalid signup request:', req.body);
        return res.status(400).json({ message: 'All fields are required and must be valid' });
    }
    const connection = await db.promise().getConnection();
    try {
        await connection.beginTransaction();

        const [existingUsers] = await connection.query('SELECT * FROM users WHERE LOWER(email) = LOWER(?)', [email]);
        console.log('Existing users check:', existingUsers);
        if (existingUsers.length > 0) {
            console.log('Email already exists:', email);
            await connection.rollback();
            connection.release();
            return res.status(409).json({ message: 'Email already exists' });
        }

        const hash = await bcrypt.hash(password, 10);
        console.log('Hashed password for signup:', hash);

        await connection.query(
            'INSERT INTO users (first_name, last_name, email, phone, password) VALUES (?, ?, ?, ?, ?)',
            [first_name, last_name, email.toLowerCase(), phone, hash]
        );
        console.log('User signed up successfully:', email);

        await connection.commit();
        connection.release();

        res.json({ message: 'Signup successful! Please sign in.' });
    } catch (error) {
        console.error('Error during signup:', error.message);
        await connection.rollback();
        connection.release();
        res.status(500).json({ message: 'Error creating user' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    console.log('Login attempt with email:', email);
    if (!email || !password) {
        console.log('Missing email or password in login request:', req.body);
        return res.status(400).json({ message: 'Email and password are required' });
    }
    const connection = await db.promise().getConnection();
    try {
        const [results] = await connection.query('SELECT * FROM users WHERE email = ?', [email]);
        console.log('Database query results for login:', results);
        if (results.length === 0) {
            console.log('User not found:', email);
            connection.release();
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        const user = results[0];
        console.log('User found:', user);
        const match = await bcrypt.compare(password, user.password);
        console.log('Password match result:', match);
        if (!match) {
            console.log('Password mismatch for user:', email);
            connection.release();
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        req.session.user = { id: user.id, email: user.email };
        console.log('User logged in, session set:', req.sessionID, req.session);
        connection.release();
        res.json({ message: 'Login successful!', redirect: '/index.html' });
    } catch (error) {
        console.error('Error during login:', error.message);
        connection.release();
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.get('/logout', (req, res) => {
    console.log('Logging out user:', req.session.user);
    req.session.destroy(err => {
        if (err) {
            console.error('Error during logout:', err.message);
            return res.status(500).json({ message: 'Error logging out' });
        }
        console.log('User logged out successfully');
        res.json({ message: 'Logged out successfully!', redirect: '/login.html' });
    });
});

app.post('/payment', csrfProtection, (req, res) => {
    try {
        console.log('Received /payment request with headers:', req.headers);
        console.log('Received /payment request body:', req.body);
        console.log('CSRF token from request:', req.headers['x-csrf-token']);
        console.log('Session in /payment:', req.sessionID, req.session);

        if (!req.session.user) {
            console.log('No user in session for /payment');
            return res.status(401).json({ message: 'User not logged in' });
        }

        const userId = req.session.user.id;
        const {
            client_name, email, phone, destination, departure_date, return_date, passengers,
            payment_method, card_number, amount, payment_status = 'Pending',
            cardholder_name, expiry, cvv, street_address, city, state, zip_code
        } = req.body;

        console.log('Processing payment for user:', userId);

        if (!client_name || !email || !destination || !departure_date || !passengers || !payment_method || !card_number || !amount || !payment_status) {
            console.log('Missing required fields in /payment request:', req.body);
            return res.status(400).json({ message: 'Missing required fields' });
        }

        db.getConnection((err, connection) => {
            if (err) {
                console.error('Error getting connection from pool:', err.message);
                return res.status(500).json({ message: 'Database connection error' });
            }

            connection.query(
                `INSERT INTO bookings (
                    user_id, client_name, email, phone, destination, departure_date, return_date, passengers,
                    payment_method, card_number, amount, payment_status, cardholder_name, expiry, cvv,
                    street_address, city, state, zip_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    userId, client_name, email, phone, destination, departure_date, return_date, passengers,
                    payment_method, card_number, amount, payment_status, cardholder_name, expiry, cvv,
                    street_address, city, state, zip_code
                ],
                (err, result) => {
                    connection.release();
                    if (err) {
                        console.error('Error saving booking:', err.message);
                        return res.status(500).json({ message: 'Error saving booking' });
                    }
                    console.log('Booking successful for user:', userId);

                    const bookingId = result.insertId;

                    const bookingData = {
                        id: bookingId,
                        client_name,
                        email,
                        phone,
                        destination,
                        departure_date,
                        return_date,
                        passengers,
                        payment_method,
                        card_number,
                        amount,
                        payment_status,
                        cardholder_name,
                        expiry,
                        cvv,
                        street_address,
                        city,
                        state,
                        zip_code
                    };

                    generateReceiptPDF(bookingData, (filePath) => {
                        if (!filePath) {
                            console.error('Failed to generate PDF receipt');
                            return res.status(500).json({ message: 'Error generating receipt' });
                        }

                        const mailOptions = {
                            from: process.env.EMAIL_USER || 'travelexplorer923@gmail.com',
                            to: email,
                            subject: 'Booking Confirmation - Travel Explorer',
                            text: `Dear ${client_name},\n\nYour booking to ${destination} on ${departure_date}${return_date ? ` to ${return_date}` : ''} for ${passengers} passenger(s) has been confirmed!\n\nPayment Details:\n- Method: ${payment_method}\n- Amount: $${amount}\n- Status: ${payment_status}\n\nPlease find your receipt attached.\n\nThank you for choosing Travel Explorer!`,
                            attachments: [
                                {
                                    filename: `receipt_${bookingId}.pdf`,
                                    path: filePath
                                }
                            ]
                        };

                        transporter.sendMail(mailOptions, (error, info) => {
                            fs.unlink(filePath, (unlinkErr) => {
                                if (unlinkErr) {
                                    console.error('Error deleting PDF file:', unlinkErr.message);
                                } else {
                                    console.log(`Deleted PDF file: ${filePath}`);
                                }
                            });

                            if (error) {
                                console.error('Error sending email:', error.message);
                            } else {
                                console.log('Email sent successfully to:', email, info.response);
                            }
                        });

                        res.json({ 
                            message: 'Booking successful! A confirmation email with your receipt has been sent to your email.',
                            redirect: `/index.html?message=${encodeURIComponent('Booking successful! A confirmation email with your receipt has been sent to your email.')}`
                        });
                    });
                }
            );
        });
    } catch (error) {
        console.error('Error in /payment:', error.message);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        console.error('CSRF token validation failed. Expected:', req.csrfToken(), 'Received:', req.headers['x-csrf-token']);
        res.status(403).json({ message: 'Invalid CSRF token' });
    } else {
        console.error('Global server error:', err.message);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
