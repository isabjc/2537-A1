
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();

const port = process.env.PORT || 3000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
app.use(express.static(__dirname + "/public"));

app.set('view engine', 'ejs');

const Joi = require("joi");

const expireTime = 1000 * 60 * 60;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({
	secret: node_session_secret,
	store: mongoStore,
    saveUninitialized: false,
    resave: true,
}));


function isValidSession(req) {
	if (req.session.authenticated) {
		return true;
	}
	return false;
}

function sessionValidation(req, res, next) {
	if (isValidSession(req)) {
		next();
	}
	else {
		res.redirect('/');
	}
}

function isAdmin(req) {
	if (req.session.user_type == 'admin') {
		return true;
	}
	return false;
}

function adminAuthorization(req, res, next) {
	if (!isAdmin(req)) {
		res.status(403);
		res.render('admin', {
			users: [],
			notAuthorized: true,
			session: req.session
		});
		return;
	}
	else {
		next();
	}
}

app.get('/', (req, res) => {
	if (!req.session.user) {
		res.render('index', {
			session: req.session
		})

	} else {
		res.redirect('/loggedIn');
	}
});

app.get('/loggedIn', (req, res) => {
	if (req.session.user) {
		let username = req.session.user;
		res.render('loggedIn', {
			user: username,
			session: req.session
		});
	}
});
app.get('/signup', (req, res) => {

	res.render('createUser', {
		errors: [],
		session: req.session
	});
});

app.post('/newuser', async (req, res) => {

	var username = req.body.username;
	var email = req.body.email;
	var password = req.body.password;
	var user_type = 'user';

	const errors = [];

	if (!username) errors.push("Please provide a user name");
	if (!email) errors.push("Please provide an email");
	if (!password) errors.push("Please provide a password");

	if (errors.length > 0) {
		return res.render('createUser', { errors, session: req.session });
	}

	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
			email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});

	const validationResult = schema.validate({ username, email, password });
	if (validationResult.error != null) {
		console.log(validationResult.error);
		res.redirect('/signup');
		return;
	}

	var hashedPassword = await bcrypt.hash(password, saltRounds);

	await userCollection.insertOne({
		username: username,
		email: email,
		password: hashedPassword,
		user_type: 'user'
	});
	console.log("Inserted user");
	
	req.session.authenticated = true;
	req.session.cookie.maxAge = expireTime;
	req.session.user = { username, email, user_type };

	res.redirect('/members');
});

app.get('/login', (req, res) => {

	res.render('login',
		{
			errors: [],
			session: req.session
		});
});

app.post('/loggingin', async (req, res) => {
	var email = req.body.email;
	var password = req.body.password;

	const schema = Joi.object({
		email: Joi.string().email().required(),
		password: Joi.string().max(20).required()

	});

	const validationResult = schema.validate({ email, password });
	if (validationResult.error != null) {
		console.log(validationResult.error);
		res.render("login", {
			errors: ['email or password is incorrect type'],
			session: req.session
		});
		return;
	}

	// finding the matching email in the db, 
	// return to array, the 1 mean included in the result, 0 mean exclude
	const result = await userCollection.find({ email: email }).project({ email: 1, username: 1, user_type: 1, password: 1, _id: 1 }).toArray();

	// length = 1 mean only 1 matching found, if not 1, 0 matching or more than 1 matching email found
	console.log(result);

	if (result.length != 1) {
		res.render('login', {
			errors: ['Email or password is incorrect'],
			session: req.session
		});
		return;
	}

	//compare hashed password
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");

		req.session.authenticated = true;
		req.session.cookie.maxAge = expireTime;
		req.session.user = { username: result[0].username, email: result[0].email };
		req.session.user_type = result[0].user_type;

		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		res.render('login', {
			errors: ['Email or password is incorrect'],
			session: req.session
		});
		return;
	}

});

app.get('/members', sessionValidation, (req, res) => {

	const images = ['dog1.gif', 'dog2.gif', 'dog3.gif'];
	//const randomImage = images[Math.floor(Math.random() * images.length)];
	let username = req.session.user;

	res.render('members', {
		user: username,
		images,
		session: req.session
	}
	);
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
	const result = await userCollection.find().project({ username: 1, user_type: 1, email: 1, _id: 1 }).toArray();
	res.render('admin', {
		users: result,
		notAuthorized: false,
		session: req.session
	});
});

app.get('/admin/:action/:username', sessionValidation, adminAuthorization, async (req, res) => {
	const username = req.params.username;
	const action = req.params.action;
	try {
		if (action == 'promote') {
			await userCollection.updateOne(
				{ username: username },
				{ $set: { user_type: 'admin' } }
			);
		} else {
			await userCollection.updateOne(
				{ username: username },
				{ $set: { user_type: 'user' } }
			);
		}
		console.log('user role is successfully change');
		res.redirect('/admin');
	} catch (error) {
		console.error('failed promoting', error);
		res.status(500).send('Internal Server Error');

	}
});


app.get('/logout', (req, res) => {
	req.session.destroy();
	res.redirect('/');
});


app.get('*dummy', (req, res) => {
	res.status(404);
	res.render('404',
		{ session: req.session }
	);
});


app.listen(port, () => {
    console.log("Node application listening on port " + port);
});