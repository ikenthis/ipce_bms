const express = require('express');
const { signup, verifyAccount, resendOTP, login, logout, forgetPassword, resetPassword } = require('../controller/authController');
const isAuthenticated = require('../middlewares/isAuthenticated');


const router = express.Router();

router.post('/signup', signup);
router.post('/verify', isAuthenticated, verifyAccount);
router.post('/resend-otp', isAuthenticated, resendOTP);
router.post('/login', isAuthenticated, login);
router.post('/logout', isAuthenticated, logout);
router.post('/forgetpassword', isAuthenticated, forgetPassword);
router.post('/resetpassword', isAuthenticated, resetPassword);


module.exports = router;