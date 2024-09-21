const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios'); // Add axios for reCAPTCHA validation
const User = require('../models/User');
const router = express.Router();

// Signup Route with reCAPTCHA
router.post('/signup', async (req, res) => {
    const { email, password, recaptchaToken } = req.body;

    try {
        // Verify reCAPTCHA
        const secretKey = process.env.RECAPTCHA_SECRET;
        const verificationURL = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaToken}`;
        
        const captchaResponse = await axios.post(verificationURL);
        if (!captchaResponse.data.success) {
            return res.status(400).json({ message: 'CAPTCHA verification failed' });
        }

        // Check if the user already exists
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();

        return res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        return res.status(500).json({ message: 'Server error' });
    }
});
