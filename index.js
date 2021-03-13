const express = require('express');
const bodyParser = require('body-parser');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');

// // NEW: MySQL database driver
const mysql = require('mysql2/promise');

const app = express();

// We import and immediately load the `.env` file
require('dotenv').config();

const port = process.env.PORT;

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

app.use(async function mysqlConnection(req, res, next) {
    try {
      req.db = await pool.getConnection();
      req.db.connection.config.namedPlaceholders = true;
  
      // Traditional mode ensures not null is respected for unsupplied fields, ensures valid JavaScript dates, etc.
      await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
      await req.db.query(`SET time_zone = '-8:00'`);
  
      await next();
  
      req.db.release();
    } catch (err) {
      // If anything downstream throw an error, we must release the connection allocated for the request
      console.log(err)
      if (req.db) req.db.release();
      throw err;
    }
  });
  


app.use(cors());

app.use(bodyParser.json());

app.post('/register', async function (req, res) {
  try {
    let user;

    // Hashes the password and inserts the info into the `user` table
    await bcrypt.hash(req.body.password, 10).then(async hash => {
      try {
        [user] = await req.db.query(`
          INSERT INTO user (username, password)
          VALUES (:username, :password);
        `, {
          username: req.body.username,
          password: hash
        });

        console.log('user', user)
      } catch (error) {
        res.json('Error creating user');
        console.log('error', error)
      }
    });

    const encodedUser = jwt.sign(
      { 
        userId: user.insertId,
        ...req.body
      },
      process.env.JWT_KEY
    );

    res.json({
      data: encodedUser,
      error: false,
      msg: ''
    });
  } catch (err) {
    res.json({
      data: null,
      error: true,
      msg: 'Error, please try again'
    });
    console.log('err', err)
  }
});


  //auth
  app.post('/log-in', async function (req, res) {
    try {
      const [[user]] = await req.db.query(`
        SELECT * FROM user WHERE username = :username
      `, {  
        username: req.body.username
      });
  
      if (!user) {
        res.json('User Name/password not found');
      }
  
      console.log('user', user)
  
      const password = `${user.password}`
  
      
  
      const compare = await bcrypt.compare(req.body.password, password);
  
      console.log('compare', compare);
  
      if (compare) {
        const payload = {
          user: user.username,
          password: user.password,
          role: 2
        }
        
        const encodedUser = jwt.sign(payload, process.env.JWT_KEY);
  
        res.json({
          data: encodedUser,
          error: false,
          msg: ''
        })
      } else {
        res.json({
          data: null,
          error: true,
          msg: 'Password not found'
        });
      }
    } catch (err) {
      res.json({
        data: null,
        error: true,
        msg: 'Error logging in'
      })
      console.log('Error in /log-in', err);
    }
  });
  
  
  

// Jwt verification checks to see if there is an authorization header with a valid jwt in it.
app.use(async function verifyJwt(req, res, next) {
  
    try {
    if (!req.headers.authorization) {
      throw(401, 'Invalid authorization');
    }
  
    const [scheme, token] = req.headers.authorization.split(' ');
  
    if (scheme !== 'Bearer') {
      throw(401, 'Invalid authorization');
    }
  
   
      const payload = jwt.verify(token, process.env.JWT_KEY);
  
         req.user = payload;
    } catch (err) {
      if (err.message && (err.message.toUpperCase() === 'INVALID TOKEN' || err.message.toUpperCase() === 'JWT EXPIRED')) {
  
        req.status = err.status || 500;
        req.body = err.message;
        req.app.emit('jwt-error', err, req);
      } else {
  
        throw((err.status || 500), err.message);
      }
      console.log(err)
    }
  
    await next();
  });

  app.get('/inventory', async function(req, res) {
    try {
      const [inventory] = await req.db.query('SELECT id, name, upc, amount FROM inventory')

      res.json({ data: inventory, error: false});
    } catch (err) {
      console.log('Error loading', err);
      res.json({
        data: null,
        error: true,
        msg: 'Error please retry'
      });
    }
  });
  
app.put('/inventory', async function(req, res) {
  try {
    await req.db.query(
      `INSERT INTO inventory (
        name,
        upc,
        amount
      ) VALUES (
        :name,
        :upc,
        :amount
       )`,
      {
        name: req.body.name,
        upc: req.body.upc,
        amount: req.body.amount
      }
    );

    res.json('/inventory success!');
  } catch (err) {
    console.log('Error in /inventory', err);
    res.json('Error sending update');
  }
});

app.post('/inventory', async function(req, res) {
  try {
    console.log('/inventory success!');

    res.json('/inventory success!')
  } catch (err) {
    
  }
});

app.delete("/deleteInventory/:id", async function (req, res) {
  try {
    await req.db.query(
      `DELETE
      FROM inventory
      WHERE upc = :id`,
      {
        id: req.params.id
       
      }
    );

    res.json("/delete success!");
  } catch (err) {
    console.log("Error in /delete", err);
    res.json("Error deleting recipe");
  }
});

app.listen(port, () => console.log(`angular-project listening at http://localhost:${port}`));