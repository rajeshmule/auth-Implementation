const Users = require('../models/user.model');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
var nodemailer = require('nodemailer');
const dotenv = require('dotenv');
dotenv.config();

var transporter = nodemailer.createTransport({
	service: 'gmail',
	auth: {
		user: process.env.EMAIL,
		pass: process.env.PASSWORD,
	},
});

exports.signUpForm = (req, res) => {
	res.render('signUp');
};
exports.signUp = async (req, res, next) => {
	try {
		const data = req.body;
		await Users.create(data);
		res.redirect('/users/signin');
	} catch (error) {
		next(error);
	}
};

exports.signInForm = (req, res) => {
	res.render('signIn');
};

exports.signIn = async (req, res, next) => {
	try {
		const { email, password } = req.body;
		const user = await Users.findOne({ email });
		if (!user) return next(error);
		const isMatch = await user.verifyPassword(password);
		if (!isMatch) return next(error);

		// log the user in by adding user's id  it to session
		req.session.userId = user.id;

		res.redirect('/dashboard');
	} catch (error) {
		next(error);
	}
};

exports.logout = (req, res, next) => {
	console.log('inside logout => ', req.session.userId);
	if (req.session) {
		// delete session object
		req.session.destroy(function (err) {
			if (err) {
				return next(err);
			} else {
				return res.redirect('/');
			}
		});
	}
};

exports.renderForgotPassword = (req, res) => {
	res.render('forgot-password');
};

exports.forgotPassword = async (req, res, next) => {
	const email = req.body.email;
	const buffer = await crypto.randomBytes(32);
	const token = buffer.toString('hex');

	try {
		const requestedUser = await Users.findOne({ email });
		if (!requestedUser) throw new Error('Enter Correct email id.');
		const updateUser = await Users.findByIdAndUpdate(
			{ _id: requestedUser._id },
			{
				resetPasswordToken: token,
				resetPasswordExpires: Date.now() + 3600000, // 1hour
			},
			{ upsert: true, new: true },
		);

		const passwordResetUrl = `${req.headers.origin}/users/password-reset/${updateUser.resetPasswordToken}`;
		// console.log(passwordResetUrl);

		var mailOptions = {
			from: process.env.EMAIL,
			to: email,
			subject: 'password resety foryour account.',
			text: `You requested for a password reset, kindly use this ${passwordResetUrl}`,
		};

		let info = await transporter.sendMail(mailOptions);
		// console.log(info.accepted);
		if (info.accepted == email) {
			res.render('resetLinkSend', { email: email });
		}
	} catch (error) {
		next(error);
	}
};

exports.renderResetPassword = (req, res) => {
	res.render('reset-password', { token: req.params.token });
};

exports.resetPassword = async (req, res, next) => {
	// console.log('token', req.params.token);
	const token = req.params.token;
	try {
		user = await Users.findOne({
			resetPasswordToken: token,
			resetPasswordExpires: {
				$gt: Date.now(),
			},
		});
		// console.log(user.id);

		if (!user) throw new Error('User Not Found.');

		if (req.body.newPassword === req.body.verifyPassword) {
			// console.log(req.body.newPassword, req.body.verifyPassword, 'true');
			var hashPassword = bcrypt.hashSync(req.body.newPassword, 10);
			const updateUser = await Users.findByIdAndUpdate(
				{ _id: user.id },
				{
					password: hashPassword,
					resetPasswordToken: undefined,
					resetPasswordExpires: undefined,
				},
				{ upsert: true, new: true },
			);
			// console.log(updateUser);
			if (!updateUser) {
				throw new Error('not reset.');
			} else {
				res.redirect('/users/signin');
			}
		}
	} catch (error) {
		next(error);
	}
};
