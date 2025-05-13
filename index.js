
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();

const port = process.env.PORT || 3000;

// getting all the info of database from .env file
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
app.use(express.static(__dirname + "/public"));

const Joi = require("joi");

const expireTime = 1000 * 60 * 60; // expire after 1 hour

// connect to database 
var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
});

// create session
app.use(session({
	secret: node_session_secret,
	store: mongoStore,
    saveUninitialized: false,
    resave: true,
}));

//home page
app.get('/', (req, res) => {
	if(!req.session.user) {
    let homepage = 
        `<a href ="/signup"><button>Sign up</button></a>
         <a href ="/login"><button>Log in</button></a>       
         `;
    res.send(homepage)

} else {
	res.redirect ('/loggedIn');
}
});

app.get('/loggedIn', (req, res) => {
	if (req.session.user){
	let loggedinhome = `<h3>Hello, ${req.session.user.username}! </h3>
	<a href ="/members"><button>Go to Member Area</button>
	<a href="/logout"><button>Logout</button>
	`;
	res.send(loggedinhome);
}

});


// sign up page
app.get('/signup', (req, res) => {
	let login = `
    <h3 style="margin-bottom: 20px">Create user</h3>
    <form action='/newuser' method='post' 
	style="display: flex; flex-direction: column; align-item: center; width: 50%; gap: 20px">
    <input name='username' type='text' placeholder='username'>
	<input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(login);
});

//createing new user and store in mongoDB
app.post('/newuser', async (req,res) => {

    var username = req.body.username;
	var email = req.body.email;
    var password = req.body.password;

	if(!username){
		res.send(`
			<span>Please provide a user name</span>
			<a href="/signup"> Try again </a>
			`);
			return;
	}

	if (!email) {
		res.send(`
			<span>Please provide an email</span>
			<a href="/signup"> Try again </a>
			`);
			return;
	}

	if(!password) {
		res.send(`
			<span>Please provide a password</span>
			<a href="/signup"> Try again </a>
			`);
			return;
	}

		// validating the input to prevent sql injection attack
	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
			email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/signup");
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({
		username: username, 
		email: email, 
		password: hashedPassword});
	console.log("Inserted user");

	req.session.user = {username, email};
    res.redirect('/members');
});

// loggin page
app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi. object({
		email: Joi.string().email().required(),
		password: Joi.string().max(20).required()

	});
	
	const validationResult = schema.validate({email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	// finding the matching email in the db, 
	// return to array, the 1 mean included in the result, 0 mean exclude
	const result = await userCollection.find({email: email}).project({email: 1, username:1, password: 1, _id: 1}).toArray();

	// length = 1 mean only 1 matching found, if not 1, 0 matching or more than 1 matching email found
	console.log(result);
	if (result.length != 1) {
		
		let failed = `
		<span>Email or password is incorrect</span>
		<a href = "/login">Try again</a>`;
		res.send(failed);
		return;
	}
	
	//compare hashed password
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");

		req.session.authenticated = true;
		req.session.cookie.maxAge = expireTime;
		req.session.user = { username: result[0].username, email: result[0].email };
		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		let passwordfailed = `
		<span>Email or password is incorrect</span>
		<a href = "/login">Try again</a>`;
		res.send(passwordfailed);
		return;
	}

});

app.get('/members', (req, res) => {
	if(!req.session.user){
		res.redirect('/');
		return;
	}

	const images = ['dog1.gif', 'dog2.gif', 'dog3.gif'];
    const randomImage = images[Math.floor(Math.random() * images.length)];
	res.send(`
        <h1>Hello, ${req.session.user.username}!</h1>
        <img src="/${randomImage}" alt="image" style="max-width: 300px;">
        <br>
        <a href="/logout"><button>Logout</button></a>
    `);

});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});


app.get('*dummy', (req,res) => {
    res.status(404);
    res.send("Page not found - 404");
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});