require('dotenv').config();
require('./config/database').connect();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());

// Import user context
const User = require('./model/user');
const { urlencoded } = require('express');

// Register user
app.post('/register', async (req, res) => {
	//reg logic here
	try {
		// Get user input
		const { first_name, last_name, email, password } = req.body;

		if (!(email && password && first_name && last_name)) {
			res.status(400).send('All fields required');
		}

		// User exist?
		const oldUser = await User.findOne({ email });

		if (oldUser) {
			return res.status(409).send('User already exists. Please login.');
		}

		// Encrypt pw
		encryptedPassword = await bcrypt.hash(password, 10);

		// Create user in DB
		const user = await User.create({
			first_name,
			last_name,
			email: email.toLowerCase(),
			password: encryptedPassword,
		});

		// Create token
		const token = jwt.sign(
			{ user_id: user._id, email },
			process.env.TOKEN_KEY,
			{
				expiresIn: '2h',
			}
		);

		// Save user token
		user.token = token;

		// Return new user
		res.status(201).json(user);
	} catch (err) {
		console.log(err);
	}
});

// Login
app.post('/login', async (req, res) => {
	// login logic here
	try {
		// Get user input
		const { email, password } = req.body;

		// Validate user input
		if (!(email && password)) {
			res.status(400).send('All input is required');
		}
		const user = await User.findOne({ email });

		if (user && (await bcrypt.compare(password, user.password))) {
			// Create pw
			const token = jwt.sign(
				{ user_id: user._id, email },
				process.env.TOKEN_KEY,
				{
					expiresIn: '2h',
				}
			);
			// Save user token
			user.token = token;

			//User
			res.status(200).json(user);
		}
	} catch (err) {
		res.status(400).send('Invalid credentials');
		console.log(err);
	}
});

const auth = require('./middleware/auth');

app.get('/welcome', auth, (req, res) => {
	res.status(200).send('Welcome!');
});

module.exports = app;
