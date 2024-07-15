const express = require('express');
const { registerUser, loginUser, sendResetLink, forgotPassword, resetPassword } = require('../controllers/userController');

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/forgot-password', forgotPassword);
router.post('/send-reset-link', sendResetLink);
router.post('/reset-password/:token', resetPassword);

module.exports = router;
