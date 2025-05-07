require('dotenv').config()

const express    = require('express')
const session    = require('express-session')
const MongoStore = require('connect-mongo')
const bcrypt     = require('bcrypt')
const Joi        = require('joi') // Joi used for validating user inputs
const { database } = require('./databaseConnection')
const saltRounds = 12; // bcrypt

// secret environment variables
const {
  MONGODB_DATABASE,
  MONGODB_SESSION_SECRET,
  NODE_SESSION_SECRET,
  PORT
} = process.env;

const app = express()
const sessionTTL = 1 * 60 * 60 // (1 hour * 60 mins * 60 secs = 1 hour total)
const port = PORT || 3000;

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
        ttl: sessionTTL
    })
  }))

  // Home page
  app.get('/', (req, res) => {
    if (req.session.user) {
      res.send(`<h1>Hello, ${req.session.user.name}</h1>` +
        `<a href="/members">Members Area</a> | <a href="/logout">Log out...</a>`)
    } else {
      res.send(
        `<h1>Welcome!</h1>` +
        `<a href="/signup">Sign up!</a> ||| <a href="/login">Log in!</a>`);
    }
  });

  // Signup page
  app.get('/signup', (req, res) => {
    res.send(`<form method="POST" action="/signup">
      Name: <input name="name"/><br/>
      Email: <input name="email"/><br/>
      Password: <input name="password" type="password"/><br/>
      <button>Sign Up</button>
      </form>
      `);
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
      return res.send(`Invalid input: ${error.details[0].message}. <a href="/signup">Go Back!!</a>`)
    }

    const hashed = await bcrypt.hash(value.password, saltRounds)
    await usersCol.insertOne({ name: value.name, email: value.email, password: hashed })
    req.session.user = { name: value.name, email: value.email }
    res.redirect('/members')
  })

  // Login page
  app.get('/login', (req, res) => {
    res.send(`<form method="POST" action="/login">
      Email: <input name="email"/><br/>
      Password: <input name="password" type="password"/><br/>
      <button>Log In</button>
      </form>
      `);
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
      return res.send(`Invalid input: ${error.details[0].message}. <a href="/login">Back</a>`)
    }

    const user = await usersCol.findOne({ email: value.email });
    if (user && await bcrypt.compare(value.password, user.password)) {
      req.session.user = { name: user.name, email: user.email };
      return res.redirect('/members');
    }
    res.send('User and password not found. <a href="/login">Try again!</a>')
  })

  // Members page (protected)
  app.get('/members', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    const images = ['images/photo1.jpg','images/photo2.jpg','images/photo3.jpg']
    const img = images[Math.floor(Math.random() * images.length)]
    res.send(
      `<h1>Hello, ${req.session.user.name}</h1>` +
      `<img src="/${img}" style="max-width:300px;"/><br/>` +
      `<a href="/logout">Log out</a>`
    );
  });

  // Logout action
  app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'))
  });

  // 404 handling
  app.use((req, res) => {
    res.status(404).send('404 Not Found')
  });

  // RUN THE SERVER!!!!!!
  app.listen(port, () => console.log(`Listening on port ${port}`))
})()
