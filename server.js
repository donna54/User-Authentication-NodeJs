// Imports
const express = require('express');
const app = express();
const cookieParser = require('cookie-parser');
const session = require('express-session');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const passport = require('passport')
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const User = require('../models/user_model');
const index = require('./routes/index');
const user = require('./routes/user');

// Defining port number
const PORT = 5000;

// Database connection
mongoose.connect('mongodb://localhost/users3').then(() => {
    console.log("Database connected");
});

// Middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser())
app.use(cors())
app.use(session({
    cookie: { maxAge: 60000 },
    secret: 'secretsession',
    saveUninitialized: false,
    resave: false
}));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http:127.0.0.1:5000/auth/google/callback"
},
    function (accessToken, refreshToken, profile, done) {
        let [err, user] = await to(getUserByProviderId(profile.emails[0]))
        if (err || user) {
            return done(err, user)
        }

        User.findOrCreate({
            emailId: profile.emails[0],
            name: profile.name.givenName,
            password: '*',
            emailConfirmation: true
        }, function (err, user) {
            return done(err, user);
        });
    }
));

// Defining routes
app.use('/user', user);
app.use('/', index);

app.get('/auth/google',
    passport.authenticate('google', { scope: ['https://www.googleapis.com/auth/plus.login'] })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        res.redirect('/index');
    });


// Starting server
app.listen(PORT, function () {
    console.log('Server is running on Port', PORT);
});