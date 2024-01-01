const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const session = require('express-session');

const app = express();

//Middleware
app.use(express.json());
app.use(cookieParser());
app.use(session({ secret: 'secret-key', resave: false, saveUninitialized: false }));

//Dummy database
const users = [];

//API Endpoints
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  res.status(201).send({ message: 'User created successfully' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ username: user.username }, 'secret-key');
    
//Set cookie
    res.cookie('token', token, { httpOnly: true });

    res.status(200).send({ message: 'Logged in successfully', token });
  } else {
    res.status(401).send({ message: 'Invalid credentials' });
  }
});

//Protected route
app.get('/protected', (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).send({ message: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, 'secret-key');
    res.status(200).send({ message: 'Protected route', user: decoded });
  } catch (error) {
    res.status(401).send({ message: 'Invalid token' });
  }
});

//Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});