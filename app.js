require('dotenv').config()

const express    = require('express')
const session    = require('express-session')
const MongoStore = require('connect-mongo')
const bcrypt     = require('bcrypt')
const Joi        = require('joi') // Joi used for validating user inputs
const { database } = require('./databaseConnection')
const { ObjectId } = require('mongodb')
const saltRounds = 12; // bcrypt

// secret environment variables
const {
  MONGODB_DATABASE,
  MONGODB_SESSION_SECRET,
  NODE_SESSION_SECRET,
  PORT
} = process.env;

const app = express()
const expireTime = 1 * 60 * 60 // (1 hour * 60 mins * 60 secs = 1 hour total)
const port = PORT || 3000;

app.set('view engine', 'ejs');

// App initialization stuff
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'));

// Async wrapper
(async () => {
  await database.connect()
  const db       = database.db(MONGODB_DATABASE);
  const usersCol = db.collection('users')

  // Session store config
  app.use(
    session({
      secret: NODE_SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({
        client: database,
        dbName: MONGODB_DATABASE,
        crypto: { secret: MONGODB_SESSION_SECRET },
        ttl: expireTime
    })
  }))

  // Home page
  app.get('/', (req, res) => {
    res.render('index', { user: req.session.user });
  });


  // Signup page
  app.get('/signup', (req, res) => {
    res.render('signup', { error: null });
  });

  // Signup handling
  app.post('/signup', async (req, res) => {

    // Validate the input with Joi
    const schema = Joi.object({
      name: Joi.string().required(),
      email: Joi.string().email().required(), 
      password: Joi.string().required() 
    });

    const { error, value } = schema.validate(req.body);

    if (error) {
      return res.render('signup', { error: `Invalid input: ${error.details[0].message}` });
    }

    const hashed = await bcrypt.hash(value.password, saltRounds)
    await usersCol.insertOne({ name: value.name, email: value.email, password: hashed, user_type: 'user' })
    req.session.user = { name: value.name, email: value.email }
    res.redirect('/members')
  })

  // Login page
  app.get('/login', (req, res) => {
    res.render('login', { error: null });
  });

  // Login handling
  app.post('/login', async (req, res) => {

    // Validate the input with Joi
    const schema = Joi.object({ 
      email: Joi.string().email().required(), 
      password: Joi.string().required() 
    });
    const { error, value } = schema.validate(req.body);

    if (error) {
      return res.render('login', { error: `Invalid input: ${error.details[0].message}` });
    }

    const user = await usersCol.findOne({ email: value.email });
    if (user && await bcrypt.compare(value.password, user.password)) {
      req.session.user = { 
        name: user.name, 
        email: user.email, 
        user_type: user.user_type
      };
      return res.redirect('/members');
    }
    return res.render('login', { error: 'User and password not found.'});
  })

  // Members page (protected)
  app.get('/members', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    const images = ['images/photo1.jpg','images/photo2.jpg','images/photo3.jpg']
    const img = images[Math.floor(Math.random() * images.length)]
    res.render('members', {
      user: req.session.user,
      img
   });
  });

  // Logout action
  app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'))
  });

  // Middleware functions for admin permissions

  // Checks if the user is authenticated
  function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) return next();
  res.redirect('/login');
  }

  // Checks if the user is an admin
  function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.user_type === 'admin') return next();
    res.status(403).render('403', { title: 'Forbidden' });
  }

  // Admin page
  app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {

    const allUsers = await usersCol.find().toArray();
    res.render('admin', {
      user: req.session.user,
      users: allUsers
    });
  });

  // Promote a user
  app.get('/admin/promote', isAuthenticated, isAdmin, async (req, res) => {
    const id = req.query.id;
    if (!id) {
      return res.redirect('/admin');
    }
    await usersCol.updateOne({ _id: new ObjectId(id) }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');
  })

  // Demote a user
  app.get('/admin/demote', isAuthenticated, isAdmin, async (req, res) => {
    const id = req.query.id;
    if (!id) {
      return res.redirect('/admin');
    }
    await usersCol.updateOne({ _id: new ObjectId(id) }, { $set: { user_type: 'user' } });
    res.redirect('/admin');
  })

  // 404 handling
  app.use((req, res) => {
    res.status(404).render('404')
  });

  // RUN THE SERVER!!!!!!
  app.listen(port, () => console.log(`Listening on port ${port}`))
})();
