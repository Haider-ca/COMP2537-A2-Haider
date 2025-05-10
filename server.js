require('dotenv').config();  // Load environment variables

const express       = require('express');
const session       = require('express-session');
const MongoStore    = require('connect-mongo');
const { MongoClient } = require('mongodb');
const bcrypt        = require('bcrypt');
const Joi           = require('joi');
const path          = require('path');

const app = express();

// Middleware Setup
app.use(express.urlencoded({ extended: true }));              // Parse form submissions
app.use(express.static(path.join(__dirname, 'public')));      // Serve static assets
app.set('view engine', 'ejs');                                // Template engine

// Environment Configuration
const {
  MONGODB_URI,
  MONGODB_SESSION_SECRET,
  PORT = 3000
} = process.env;


// Main Application Logic
async function main() {
  // Database Connection
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const users = client.db().collection('users');

  // Session Configuration with MongoDB store (1-hour TTL)
  app.use(session({
    secret: MONGODB_SESSION_SECRET,
    store: MongoStore.create({ client, collectionName: 'sessions', ttl: 3600 }),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600 * 1000 }
  }));


  // Route Definitions
  
  // Home page (displays login status)
  app.get('/', (req, res) => {
    res.render('home', { user: req.session.user });
  });

  // Signup: render form & process new user registration
  app.get('/signup', (req, res) => res.render('signup', { error: null }));
  app.post('/signup', async (req, res) => {
    const schema = Joi.object({
      name:     Joi.string().max(50).required(),
      email:    Joi.string().email().required(),
      password: Joi.string().min(6).required()
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.render('signup', { error: error.details[0].message });

    const { name, email, password } = value;
    if (await users.findOne({ email })) {
      return res.render('signup', { error: 'Email already registered' });
    }

    // Securely hash password before saving
    const hash = await bcrypt.hash(password, 10);
    await users.insertOne({ name, email, password: hash });

    req.session.user = { name, email };
    res.redirect('/members');
  });

  // Login: render form & authenticate existing users
  app.get('/login', (req, res) => res.render('login', { error: null }));
  app.post('/login', async (req, res) => {
    const schema = Joi.object({
      email:    Joi.string().email().required(),
      password: Joi.string().required()
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.render('login', { error: error.details[0].message });

    const { email, password } = value;
    const user = await users.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Invalid email or password' });
    }

    req.session.user = { name: user.name, email };
    res.redirect('/members');
  });

  // Members-only page (requires login)
  app.get('/members', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    const imgs = ['image1.jpg', 'image2.jpg', 'image3.jpg'];
    const randomImage = imgs[Math.floor(Math.random() * imgs.length)];
    res.render('members', { user: req.session.user, randomImage });
  });

  // Logout and destroy session
  app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
  });

  // 404 handler for unmatched routes
  app.use((req, res) => {
    res.status(404).render('404');
  });

  // Start listening
  app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
}

main().catch(console.error);
