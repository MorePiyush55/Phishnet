require('dotenv').config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: process.env.FRONTEND_URL || true, credentials: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

app.use('/auth', authRoutes);

app.get('/', (req, res) => {
  res.send('PhishNet Node OAuth backend - visit /auth/google to initiate login');
});

app.listen(PORT, () => {
  console.log(`PhishNet Node backend listening on port ${PORT}`);
});