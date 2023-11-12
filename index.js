const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { encrypt, decrypt } = require('./utils/crypt.js');

const app = express();

require('dotenv').config();

app.use(express.json());

app.use((req, res, next) => {
	res.header('Access-Control-Allow-Origin', 'https://passwordinator.netlify.app');
	next();
});

app.use(cors());

const db = mysql.createConnection({
	user: 'root',
	host: 'containers-us-west-179.railway.app',
	password: process.env.MYSQLPASSWORD,
	database: 'railway',
	port: process.env.MYSQLPORT,
});

app.get('/saved/:userID', authorizationToken, async (req, res) => {
	const userID = req.params['userID'];

	await db.query(`SELECT * FROM passwords WHERE userID = ?`, [userID], (err, results) => {
		if (err) {
			console.log(err);
		} else {
			results.forEach((passObj) => {
				passObj.username = decrypt(passObj.username, process.env.USECRET);
				passObj.password = decrypt(passObj.password, process.env.PSECRET);
			});

			res.status(200).send(results);
		}
	});

	db.end();
});

app.put('/saved/:userID/:passID', authorizationToken, async (req, res) => {
	const userID = req.params['userID'];
	const passID = req.params['passID'];

	const website = req.body.website;
	const username = encrypt(req.body.username, process.env.USECRET);
	const password = encrypt(req.body.password, process.env.PSECRET);

	await db.query(
		'UPDATE passwords SET website = ?, username = ?, password = ? WHERE userID = ? AND passwordID = ?',
		[website, username, password, userID, passID],
		(err, results) => {
			if (err) {
				console.log(err);
			} else {
				res.status(200).send('Successfully updated entry.');
			}
		}
	);

	db.end();
});

app.delete('/saved/:userID/:passID', authorizationToken, async (req, res) => {
	const userID = req.params['userID'];
	const passID = req.params['passID'];

	db.query('DELETE FROM passwords WHERE userID = ? and passwordID = ?', [userID, passID], (err, results) => {
		if (err) {
			console.log(err);
		} else {
			res.status(200).send('Successfully removed.');
		}
	});

	db.end();
});

app.post('/add', authorizationToken, async (req, res) => {
	const userID = req.body.userID;
	const encryptedU = encrypt(req.body.username, process.env.USECRET);
	const encryptedP = encrypt(req.body.password, process.env.PSECRET);
	const timeCreated = req.body.timeCreated;
	const website = req.body.website;

	await db.query(
		'INSERT INTO passwords (userID, username, password, timeCreated, website) VALUES (?,?,?,?,?)',
		[userID, encryptedU, encryptedP, timeCreated, website],
		(err, result) => {
			if (err) {
				console.log(err);
			} else {
				res.send(result);
			}
		}
	);

	db.end();
});

app.post('/signup', async (req, res) => {
	const username = req.body.username;
	const email = encrypt(req.body.email, process.env.EMSECRET);
	const hashedPassword = await bcrypt.hash(req.body.password, 10);

	await db.query('SELECT * FROM users WHERE email = ?', [email], (err, result) => {
		if (result.length > 0) {
			res.send({ message: 'Email already exists. Please select another.' });
		} else {
			db.query(
				'INSERT INTO users (username, password, email) VALUES (?,?,?)',
				[username, hashedPassword, email],
				(err, result) => {
					if (err) {
						res.send({ err: err });
					} else {
						const userID = result.insertId;
						const token = jwt.sign({ userID }, process.env.ACCESS_TOKEN);

						res.json({
							auth: true,
							token: token,
							result: { id: userID, username: username },
						});
					}
				}
			);
		}
	});

	db.end();
});

app.post('/login', async (req, res) => {
	const username = req.body.username;
	const password = req.body.password;

	await db.query('SELECT * FROM users WHERE username = ?', [username], (err, result) => {
		if (err) {
			res.send({ err: err });
		}

		if (result.length > 0) {
			bcrypt.compare(password, result[0].password, async (error, response) => {
				if (response) {
					const userID = result[0].id;
					const token = jwt.sign({ userID }, process.env.ACCESS_TOKEN);

					// req.session.user = result;
					res.json({
						auth: true,
						token: token,
						result: { id: userID, username: result[0].username },
					});
				} else {
					res.send({ message: 'Wrong username/password combination.' });
				}
			});
		} else {
			res.send({ message: 'No user found.' });
		}
	});

	db.end();
});

app.post('/logout', async (req, res) => {
	const userID = req.body.userID;
	const token = req.body.token;

	// log user out on client side and add current access token to blacklist db
	await db.query('INSERT INTO blacklist (userid, token) VALUES (?, ?)', [userID, token], (err, result) => {
		if (err) {
			console.log(err);
		} else {
			res.json({
				auth: false,
				token: null,
				result: null,
			});
		}
	});

	db.end();
});

function authorizationToken(req, res, next) {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];

	if (token == null) return res.sendStatus(401);
	db.query('SELECT COUNT(*) AS total FROM blacklist WHERE token = ?', [token], (err, result) => {
		if (err) {
			console.log(err);
		}

		if (result[0].total > 0) {
			res.sendStatus(403);
		} else {
			jwt.verify(token, process.env.ACCESS_TOKEN, (err, userID) => {
				if (err) return res.sendStatus(403);
				req.userID = userID;
				next();
			});
		}
	});
}

app.listen(`${process.env.PORT}`, () => {
	console.log(`running server on port ${process.env.PORT}`);
});
