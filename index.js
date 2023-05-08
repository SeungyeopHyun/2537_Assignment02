require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");
const path = require("path");
const { ObjectId } = require('mongodb');



const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));


app.get('/', (req, res) => {
  let loggedIn = false;
  let username = '';

  if (req.session && req.session.user) {
    loggedIn = true;
    username = req.session.user.name;
  }

  res.render('index', { loggedIn, username, session: req.session });
});

app.get('/Activities', function(req, res) {
  res.render('Activities');
});

// Replace the rest of your app.get and app.post routes with their EJS equivalents
// Example: app.get('/signup', (req, res) => { res.render('signup'); });

app.get('/nosql-injection', async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.render('nosql-injection', {
      message: 'No user provided - try /nosql-injection?user=name or /nosql-injection?user[$ne]=name',
      error: false,
      users: []
    });
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.render('nosql-injection', {
      message: '',
      error: true,
      users: []
    });
    return;
  }

  const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

  console.log(result);

  res.render('nosql-injection', {
    message: '',
    error: false,
    users: result
  });
});

app.get('/signup', (req, res) => {
  res.render('signup', { session: req.session });
});

const userSchema = Joi.object({
  name: Joi.string().min(1).max(255).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).max(255).required(),
});


app.post('/signup', async (req, res) => {
  // Validate input and check for missing fields
  const result = userSchema.validate(req.body);
  if (result.error) {
    res.status(400).send(result.error.details[0].message);
    return;
  }

  // Add user to MongoDB, create session, and redirect to /members
  try {
    const existingUser = await userCollection.findOne({ email: req.body.email });

    if (existingUser) {
      res.status(400).send('Email already exists');
      return;
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const newUser = {
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
      type: 'user'
    };


    await userCollection.insertOne(newUser);
    req.session.user = newUser;
    res.redirect('/members');
  } catch (err) {
    console.log(err);
    res.status(500).send('Server error');
  }
});


app.get('/login', (req, res) => {
  res.render('login', { session: req.session });
});

app.post('/login', async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().email().required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect('/login');
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ email: 1, password: 1, name: 1, _id: 1 }) // Add 'name' field to the projection
    .toArray();

  console.log(result);
  if (result.length != 1) {
    console.log('user not found');
    res.redirect('/login');
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log('correct password');
    req.session.authenticated = true;
    req.session.user = {
      email: email,
      name: result[0].name // Assuming the user's name is stored in the 'name' field
    };
    req.session.cookie.maxAge = expireTime;

    res.redirect('/');
    return;
  } else {
    console.log('user or password not found');
    res.redirect('/loginSubmit?error=userNotFound');
    return;
  }
});


app.get('/loginSubmit', (req, res) => {
  let error;
  if (req.query.error === 'userNotFound') {
    error = 'User or password not found. Please check your email and password and try again.';
  } else {
    error = '';
  }

  res.render('loginSubmit', { error: error, session: req.session });
});


app.get('/members', (req, res) => {
  if (!req.session.user) {
    res.redirect('/');
    return;
  }

  const user = req.session.user; // Retrieve the user object from the session

  // Create an array of image URLs
  const imageUrls = [1, 2, 3].map(num => `image${num}.jpg`);

  res.render('members', { user: user, session: req.session, imageUrls: imageUrls });
});

app.use(express.static(__dirname + "/public"));




app.get('/admin', async (req, res) => {
  if (!req.session.user) {
    res.redirect('/login');
    return;
  }

  // Check if the current user is an admin (assuming you have a 'type' field in your user schema)
  const currentUser = await userCollection.findOne({ email: req.session.user.email });
  if (currentUser.type !== 'admin') {
    res.status(403).send('Forbidden');
    return;
  }

  const users = await userCollection.find({}).toArray();
  res.render('admin', { users: users, session: req.session });
});


app.get('/promote/:userId', async (req, res) => {
  const userId = req.params.userId;
  await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { type: 'admin' } });
  res.redirect('/admin');
});

app.get('/demote/:userId', async (req, res) => {
  const userId = req.params.userId;
  await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { type: 'user' } });
  res.redirect('/admin');
});



app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
      res.status(500).send('Server error');
      return;
    }

    res.redirect('/');
  });
});



app.use((req, res, next) => {
  res.status(404).render('404', { session: req.session });
});


app.listen(port, () => {
  console.log("Node application listening on port " + port);
});

