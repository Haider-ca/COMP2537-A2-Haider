require('dotenv').config();

const fs = require('fs');
const mime = require('mime');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');

const app = express();

// Middleware Setup
app.use(express.urlencoded({ extended: true }));                   // Parse form submissions
app.use(express.static(path.join(__dirname, 'public')));           // Serve static assets
app.set('view engine', 'ejs');                                     // Template engine
app.set('views', path.join(__dirname, 'views'));                   // Templates folder

// Environment Configuration
const {
  MONGODB_URI,
  MONGODB_SESSION_SECRET,
  PORT = 3000
} = process.env;

// Main Application Logic
async function main() {
  // Connect to MongoDB
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const users = client.db().collection('users');

  // Session configuration (store in MongoDB, 1h TTL)
  app.use(session({
    secret: MONGODB_SESSION_SECRET,
    store: MongoStore.create({ client, collectionName: 'sessions', ttl: 3600 }),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600 * 1000 }
  }));

  // Authorization Middleware
  function ensureLoggedIn(req, res, next) {
    if (req.session.user) return next();
    res.redirect('/login');
  }

  function ensureAdmin(req, res, next) {
    if (req.session.user?.user_type === 'admin') return next();
    res.status(403).render('403', {
      user: req.session.user,
      title: '403 Forbidden'
    });
  }

  // Route Definitions

  // Homepage
  app.get('/', (req, res) => {
    res.render('home', {
      user: req.session.user,
      title: 'Home'
    });
  });

  // Signup
  app.get('/signup', (req, res) => {
    res.render('signup', {
      user: req.session.user,
      error: null,
      title: 'Sign Up'
    });
  });

  app.post('/signup', async (req, res) => {
    const schema = Joi.object({
      name: Joi.string().max(50).required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(6).required()
    });
    const { error, value } = schema.validate(req.body);
    if (error) {
      return res.render('signup', {
        user: req.session.user,
        error: error.details[0].message,
        title: 'Sign Up'
      });
    }

    const { name, email, password } = value;
    if (await users.findOne({ email })) {
      return res.render('signup', {
        user: req.session.user,
        error: 'Email already registered',
        title: 'Sign Up'
      });
    }

    const hash = await bcrypt.hash(password, 10);
    await users.insertOne({
      name,
      email,
      password: hash,
      user_type: 'user'
    });

    req.session.user = { name, email, user_type: 'user' };
    res.redirect('/members');
  });

  // Login
  app.get('/login', (req, res) => {
    res.render('login', {
      user: req.session.user,
      error: null,
      title: 'Log In'
    });
  });

  app.post('/login', async (req, res) => {
    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().required()
    });
    const { error, value } = schema.validate(req.body);
    if (error) {
      return res.render('login', {
        user: req.session.user,
        error: error.details[0].message,
        title: 'Log In'
      });
    }

    const { email, password } = value;
    const user = await users.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', {
        user: req.session.user,
        error: 'Invalid email or password',
        title: 'Log In'
      });
    }

    req.session.user = {
      name: user.name,
      email,
      user_type: user.user_type
    };
    res.redirect('/members');
  });

  // Members 
  app.get('/members', ensureLoggedIn, (req, res) => {
    const images = fs
      .readdirSync(path.join(__dirname, 'public', 'images'))
      .filter(f => /\.(jpe?g|png|gif)$/i.test(f));

    res.render('members', {
      user: req.session.user,
      images,
      title: 'Members'
    });
  });

  // Admin Dashboard 
  app.get('/admin', ensureLoggedIn, ensureAdmin, async (req, res) => {
    const allUsers = await users.find().toArray();
    res.render('admin', {
      user: req.session.user,
      users: allUsers,
      title: 'Admin'
    });
  });

  // Promote a user to admin
  app.get('/admin/promote/:email', ensureLoggedIn, ensureAdmin, async (req, res) => {
    await users.updateOne(
      { email: req.params.email },
      { $set: { user_type: 'admin' } }
    );
    res.redirect('/admin');
  });

  // Demote an admin to user
  app.get('/admin/demote/:email', ensureLoggedIn, ensureAdmin, async (req, res) => {
    await users.updateOne(
      { email: req.params.email },
      { $set: { user_type: 'user' } }
    );
    res.redirect('/admin');
  });

  // Delete an image (admin only)
  app.get(
    '/admin/delete-image/:filename',
    ensureLoggedIn,
    ensureAdmin,
    (req, res) => {
      const { filename } = req.params;
      const filePath = path.join(__dirname, 'public', 'images', filename);

      const type = mime.getType(filePath) || '';
      if (!['image/jpeg', 'image/png', 'image/gif'].includes(type)) {
        return res.status(400).send("Not a supported image type.");
      }

      fs.unlink(filePath, err => {
        if (err) console.error("Delete failed:", err);
        res.redirect('/members');
      });
    }
  );

  // Logout
  app.get('/logout', ensureLoggedIn, (req, res) => {
    req.session.destroy(() => {
      res.redirect('/');
    });
  });

  // 404 handler
  app.use((req, res) => {
    res.status(404).render('404', {
      user: req.session.user,
      title: 'Page Not Found'
    });
  });

  // Start server
  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
}

main().catch(console.error);
