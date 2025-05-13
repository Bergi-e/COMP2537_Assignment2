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
    /** OLD
    res.send(`<form method="POST" action="/signup">
      Name: <input name="name"/><br/>
      Email: <input name="email"/><br/>
      Password: <input name="password" type="password"/><br/>
      <button>Sign Up</button>
      </form>
      `);
      */
    res.render('signup');
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
      // OLD return res.send(`Invalid input: ${error.details[0].message}. <a href="/signup">Go Back!!</a>`)
      res.render('signup', { error: 'Invalid input: ${error.details[0].message}' });
    }

    const hashed = await bcrypt.hash(value.password, saltRounds)
    await usersCol.insertOne({ name: value.name, email: value.email, password: hashed })
    req.session.user = { name: value.name, email: value.email }
    res.redirect('/members')
  })

  // Login page
  app.get('/login', (req, res) => {
    res.render('login');

    /** OLD:
      res.send(`<form method="POST" action="/login">
      Email: <input name="email"/><br/>
      Password: <input name="password" type="password"/><br/>
      <button>Log In</button>
      </form>
      `);
      */
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
      // OLD: return res.send(`Invalid input: ${error.details[0].message}. <a href="/login">Back</a>`)
      res.render('login', { error: 'Invalid input: ${error.details[0].message}' });
    }

    const user = await usersCol.findOne({ email: value.email });
    if (user && await bcrypt.compare(value.password, user.password)) {
      req.session.user = { name: user.name, email: user.email };
      return res.redirect('/members');
    }
    // OLD: res.send('User and password not found. <a href="/login">Try again!</a>')
    return res.render('login', { error: 'User and password not found.'});
  })

  // Members page (protected)
  app.get('/members', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    const images = ['images/photo1.jpg','images/photo2.jpg','images/photo3.jpg']
    const img = images[Math.floor(Math.random() * images.length)]
    /** OLD:
    res.send(
      `<h1>Hello, ${req.session.user.name}</h1>` +
      `<img src="/${img}" style="max-width:300px;"/><br/>` +
      `<a href="/logout">Log out</a>`
    );
    */
   res.render('members');
  });

  // Logout action
  app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'))
  });

  // 404 handling
  app.use((req, res) => {
    res.status(404).render('404')
  });

  // RUN THE SERVER!!!!!!
  app.listen(port, () => console.log(`Listening on port ${port}`))
})()
