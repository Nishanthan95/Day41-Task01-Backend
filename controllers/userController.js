const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const auth = require('../utils/auth');
const randomstring = require("randomstring");

// Environment variables
const { EMAIL_USER, EMAIL_PASS, FRONTEND_URL, JWT_SECRET } = process.env;

// Email setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});




const registerUser = async (req, res) => {
    const { email, password } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).send('User already exists.');

        const hashedPassword = await auth.hashPassword(password);
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();

        res.status(201).send('User registered successfully.');
    } catch (err) {
        res.status(500).send(err.message);
    }
};

const loginUser = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send('User not found.');

        const isMatch = await auth.hashCompare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid credentials.');

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({
            message: 'Login successful',
            token: token
        });
    } catch (err) {
        res.status(500).send(err.message);
    }
};

const sendResetLink = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).send('User not found.');

        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const resetLink = `${FRONTEND_URL}/reset-password/${token}`;
        const mailOptions = {
            from: EMAIL_USER,
            to: user.email,
            subject: "Password-Reset-Link",
            html: `
                <p> Dear ${user.email}, </p>
                <p>Sorry to hear you’re having trouble logging into your account. We got a message that you forgot your password. If this was you, you can get right back into your account or reset your password now. </p>
                <p> Click the following Link to reset your password: <a href="${resetLink}">Reset Password</a> </p>
                <p>If you didn’t request a login link or a password reset, you can ignore this message. </p>
                <p> Only people who know your account password or click the login link in this email can log into your account. </p>
            `
        };

        transporter.sendMail(mailOptions, async (error, info) => {
            if (error) {
                console.error('Error sending email:', error);
                return res.status(500).send({
                    message: "Failed to send the password reset mail",
                    error: error.message
                });
            } else {
                console.log("Password reset email sent: " + info.response);
                await user.save();
                res.status(201).send({
                    message: "Password reset mail sent successfully"
                });
            }
        });
    } catch (error) {
        console.log(error);
        res.status(500).send({
            message: "Internal Server Error",
            error: error.message
        });
    }
};


const forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).send('User not found.');

        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const resetLink = `${FRONTEND_URL}/reset-password/${token}`;
        const mailOptions = {
            from: EMAIL_USER,
            to: user.email,
            subject: "Password-Reset-Link",
            html: `
                <p> Dear ${user.email}, </p>
                <p>Sorry to hear you’re having trouble logging into your account. We got a message that you forgot your password. If this was you, you can get right back into your account or reset your password now. </p>
                <p> Click the following Link to reset your password: <a href="${resetLink}">Reset Password</a> </p>
                <p>If you didn’t request a login link or a password reset, you can ignore this message. </p>
                <p> Only people who know your account password or click the login link in this email can log into your account. </p>
            `
        };

        transporter.sendMail(mailOptions, async (error, info) => {
            if (error) {
                console.error('Error sending email:', error); // Log the detailed error
                return res.status(500).send({
                    message: "Failed to send the password reset mail",
                    error: error.message 
                });
            } else {
                console.log("Password reset email sent: " + info.response);
                user.randomString = token;
                await user.save();
                res.status(201).send({
                    message: "Password reset mail sent successfully"
                });
            }
        });
    } catch (error) {
        console.log(error);
        res.status(500).send({
            message: "Internal Server Error",
            error: error.message 
        });
    }
};




const resetPassword = async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) return res.status(400).send('Password reset token is invalid or has expired.');

        const hashedPassword = await auth.hashPassword(password);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).send('Password has been updated.');
    } catch (err) {
        res.status(500).send(err.message);
    }
};




module.exports = {
    registerUser,
    loginUser,
    sendResetLink,
    forgotPassword,
    resetPassword
};
