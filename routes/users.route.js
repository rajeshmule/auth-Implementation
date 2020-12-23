var express = require('express');
var router = express.Router();

const controller = require('../controllers/users.controller');

router.route('/signup').get(controller.signUpForm).post(controller.signUp);

router.route('/signin').get(controller.signInForm).post(controller.signIn);

router.get('/logout', controller.logout);

router
	.route('/forgot-password')
	.get(controller.renderForgotPassword)
	.post(controller.forgotPassword);

router
	.route('/password-reset/:token')
	.get(controller.renderResetPassword)
	.post(controller.resetPassword);

module.exports = router;
