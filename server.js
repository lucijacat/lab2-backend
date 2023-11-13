const express = require('express')
const mysql = require('mysql2')
const cors = require('cors')
const bcrypt = require('bcrypt')
const saltRounds = 10

const app = express()

app.use(express.json())
app.use(cors())
app.use(express.static('build'))

const db = mysql.createConnection({
    host: process.env.MYSQL_HOST || 'localhost',
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE || 'lab'
})

app.get('/', (req, res) => {
    const sql = "SELECT * FROM books";
    db.query(sql, (err, result) => {
        if(err) return res.json(err);
        return res.json(result);
    })
})

app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const broken = req.body.broken;

    if(broken === true) {
        db.query(`SELECT * FROM users WHERE user = ?`,
        [username], 
        (err, result) => {
            if(err) {
                res.send({err: err});
            }
            if(result.length > 0) {
                if(result[0].password === password) {
                    res.send({isAuthenticated: true, user: result[0] });
                } else {
                    res.send({isAuthenticated: false, message: "Password incorrect"});
                }
            } else {
                res.send({isAuthenticated: false, message: "Username incorrect"});
            }
        })
    } else {
        db.query(`SELECT * FROM users WHERE user = ?`,
        [username], 
        (err, result) => {
            if(err) {
                console.log(err)
                res.send({err: err});
            }
            
            if(result.length > 0) {
                bcrypt.compare(password, result[0].password, (error, response) => {
                    if(response) {
                        res.send({isAuthenticated: true, user: result[0] });
                    } else {
                        res.send({isAuthenticated: false, message: "Username/password incorrect"});
                    }
                })
            } else {
                res.send({isAuthenticated: false, message: "Username/password incorrect"});
            }
        })
    }
})

app.post('/register', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const broken = req.body.broken;

    if(broken === true) {
        db.query(`INSERT INTO users (user, password) VALUES (?,?)`, 
        [username, password], 
        (err, result) => {
            res.send({err: err});
        }
        );
    } else {
        if (password.length < 8) {
            return res.send({message: "Password length must be at least 8 characters."});
        } else if (password === username) {
            return res.send({message: "Password and username must be different"});
        }
        bcrypt.hash(password, saltRounds, (err, hash) => {
            if(err) {
                res.send({err: err});
            }
            db.query(`INSERT INTO users (user, password) VALUES (?,?)`, 
            [username, hash], 
            (err, result) => {
                console.log(err)
                return res.status(500).json({ error: err });
            }
            );
        })
    }
})

app.get('/search', (req, res) => {
    const searchQuery = req.query.title; 
    const injection = req.query.injection; 

    if (!searchQuery) {
        return res.status(400).json({ error: 'Search query not provided' });
    }

    if (injection === "true") {
        const sql = `SELECT * FROM books WHERE name = "` + searchQuery + `"`;
        db.query(sql, (err, result) => {
            if (err) {
                console.error('Error executing search query');
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            return res.json(result);
        })
    
    } else {
        const sql = `SELECT * FROM books WHERE name = ?`;
        const searchTerm = `${searchQuery}`
        db.query(sql, [searchTerm], (err, result) => {
            if (err) {
                console.error('Error executing search query:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            return res.json(result);
        })
    }
})

const port = process.env.PORT || 8800
app.listen(port, () => {
  console.log(`Server is online on port: ${port}`)
})