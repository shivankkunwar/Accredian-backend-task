const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

const db = mysql.createConnection({
 host: process.env.DB_HOST,
 user: process.env.DB_USER,
 password: process.env.DB_PASS,
 database: process.env.DB_NAME
});

db.connect(err => {
 if (err) throw err;
 console.log('Database is connected successfully !');
});

app.post('/signup', (req, res) => {
 const { username, email, password } = req.body;

 db.query(
   'SELECT * FROM users WHERE email = ?',
   [email],
   (err, result) => {
     if (err) throw err;

     if (result.length > 0) {
       return res.status(401).send({ message: 'Email already exists' });
     }

     const hashedPassword = bcrypt.hashSync(password, 10);

     db.query(
       'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
       [username, email, hashedPassword],
       (err, result) => {
         if (err) throw err;

         const token = jwt.sign({ id: result.insertId }, 'secret_key', {
           expiresIn: 86400 
         });

         res.status(200).send({ auth: true, token: token });
       }
     );
   }
 );
});

app.post('/login', (req, res) => {
 const { email, password } = req.body;

 db.query(
   'SELECT * FROM users WHERE email = ?',
   [email],
   (err, result) => {
     if (err) throw err;

     if (result.length > 0 && bcrypt.compareSync(password, result[0].password)) {
       const token = jwt.sign({ id: result[0].id }, 'secret_key', {
         expiresIn: 86400 
       });

       res.status(200).send({ auth: true, token: token });
     } else {
       res.status(401).send({ auth: false, token: null, message: 'Invalid email or password' });
     }
   }
 );
});

app.listen(port, () => {
 console.log(`Server is running on port ${port}`);
});
