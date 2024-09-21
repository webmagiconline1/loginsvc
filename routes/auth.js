const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const router = express.Router();

// Set up session
router.use(session({
    secret: 'your-session-secret',
    resave: false,
    saveUninitialized: true
}));

// Initialize Passport
router.use(passport.initialize());
router.use(passport.session());

// Serialize and deserialize user
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    const user = await User.findById(id);
    done(null, user);
});

// Google OAuth strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Check if user already exists
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
            // Create a new user
            user = new User({
                googleId: profile.id,
                email: profile.emails[0].value,
                name: profile.displayName,
            });
            await user.save();
        }
        done(null, user);
    } catch (error) {
        done(error, null);
    }
}));

// Signup Route with reCAPTCHA
router.post('/signup', [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
    const { email, password, recaptchaToken } = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        // Verify reCAPTCHA (scrum-11)
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

// Auth Routes
router.get('/auth/google', passport.authenticate('google', {
    scope: ['profile', 'email']
}));

router.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        // Successful authentication, redirect home or send token.
        res.redirect('/'); // Or send a JWT token
    }
);

module.exports = router;
