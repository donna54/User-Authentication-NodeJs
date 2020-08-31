// Imports
require('dotenv').config();
const User = require('../models/user_model');
const jwt = require('jsonwebtoken');
var expressJwt = require('express-jwt');
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');

// Method to send email
const sendEmail = (userMail, resetMode, token, next) => {
    const transpoter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: `${process.env.EMAIL_ADDRESS}`,
            pass: `${process.env.EMAIL_PASSWORD}`
        }
    });

    const mailOptions = {
        from: `${process.env.EMAIL_ADDRESS}`,
        to: `${userMail}`,
        subject: resetMode ? 'Reset Your Account Password' : 'Email Verification Link',
        html: resetMode ?
            `<h2> RESET PASSWORD <h2>
        <h3> Please Click on the following link to reset your password with one hour of receiving it<h3>
        <a href="http://localhost:5000/reset/${token}">RESET YOUR PASSWORD </a>
        <h2> If you did not request this, please ignore this email and your password will remain unchanged <h2>
        `
            :
            `<h2> EMAIL VERIFICATION <h2>
        <h3> Please Click on the following complete your email verification with one hour of receiving it<h3>
        <a href="http://localhost:5000/user/emailVerification?token=${token}">EMAIL VERIFICATION </a>
        <h2> If you did not request this, please ignore this email and your password will remain unchanged <h2>
        `
    }

    transpoter.sendMail(mailOptions, (err, response) => {
        if (err) {
            next(err);
        } else {
            next();
        }
    })
}

// Method to update after email verification
exports.emailactivate = (req, res) => {
    const token = req.query.token;
    if (token) {
        jwt.verify(token, process.env.SECRET, (err, decodedToken) => {
            if (err) {
                return res.status(400).json({
                    error: "Incorrect Link"
                })
            }
            const { emailId } = decodedToken;
            User.findOneAndUpdate({ emailId }, {
                emailConfirmation: true
            }, (err, user) => {
                if (err) {
                    return res.status(400).json({
                        error: "User already exists linked with this emailId"
                    })
                } else {
                    return res.status(200).json({
                        message: "Email verified"
                    })
                }
            })
        })
    }
    else {
        return res.status(500).json({
            error: "Something went wrong"
        })
    }
};

// Method for resending activation email
exports.resendActivation = (req, res) => {
    const { emailId } = req.body;
    User.findOne({ emailId }).exec((err, user) => {
        if (!user) {
            res.status(404).json({
                error: "email Id does not exists"
            })
        }
        const token = jwt.sign({ emailId }, process.env.SECRET, { expiresIn: '20m' });
        sendEmail(emailId, false, token, (err) => {
            if (err) {
                return res.status(403).json({
                    error: "Invalid Email Id"
                });
            } else {
                return res.status(200).json({
                    message: `Email has been send on ${emailId}, Kindly check`
                });
            }
        });
    });
}

// Method for signup
exports.signup = (req, res, next) => {
    // Check if user exists
    const { emailId } = req.body
    User.findOne({ emailId }).exec((err, user) => {
        if (user) {
            return res.status(400).json({
                error: "User already exists linked with this emailId"
            })
        }
    });

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({
            error: errors
        });
    }

    const token = jwt.sign({ emailId }, process.env.SECRET, { expiresIn: '20m' });
    sendEmail(emailId, false, token, (err) => {
        if (err) {
            return res.status(403).json({
                error: "Invalid email ID"
            });
        }
        else {
            // Encrypt password
            bcrypt.genSalt(10, function (err, salt) {
                bcrypt.hash(req.body.password, salt, function (err, hash) {
                    if (err) {
                        return res.status(500).json({
                            error: "Error*",
                            message: err
                        });
                    }
                    else {
                        const user = new User({
                            emailId: req.body.emailId,
                            password: hash,
                            name: req.body.name,
                            salt: salt
                        });
                        user.save().then(function (result) {
                            // console.log(result);
                            res.status(200).json({
                                success: 'New user has been created'
                            });
                        }).catch(error => {
                            res.status(500).json({
                                error: error
                            });
                        });
                    }
                })
            })
        }
    })
}

// Method for signin
exports.signin = (req, res) => {
    const errors = validationResult(req)
    const { emailId, password } = req.body;
    if (!errors.isEmpty()) {
        return res.status(422).json({
            error: [errors.array()[0].msg, errors.array()[0].param]
        })

    }

    User.findOne({ emailId }, (err, user) => {
        if (!user) {
            console.log("user not found");
            return res.status(404).json({
                error: "USER_NOT_FOUND"
            });
        } else if (user.emailConfirmation === false) {
            console.log("email verification required");
            return res.status(403).json({
                error: "EMAIL_VERIFICATION_REQUIRED"
            });
        }
        else if (err) {
            console.log(err);
            return res.status(500).json({
                error: "SERVER_ERROR"
            });
        } else if (!user.authenticate(password, user.password)) {
            console.log("authentication failed");
            return res.status(401).json({
                error: "Email and Password don't match"
            });
        }

        const token = jwt.sign({ _id: user._id }, process.env.SECRET)
        // Put Token in user browser Cookie
        res.cookie("token", token, { expire: new Date() + 9999 })
        // send res to FrontEnd
        const { _id, name, email } = user;
        return res.json({ token, user: { _id, name, email } })
    })

};

// Method for signout
exports.signout= (req,res) => {
    // clear cookie => clear token 
    res.clearCookie("token")
    res.json({
        message: "Signout successful"
    });

};

// Method for resetting password
exports.resetpass = (req, res) => {
    const { emailId } = req.body;
    User.findOne({ emailId }).exec((err, user) => {
        if(user === null){
            return res.status(404).send({
                error: "User does not exists"
            });
        }else if(user.emailConfirmation === false){
            return res.status(403).send({
                error: "email verification not competed"
            })
        }else{
            const id = user._id;
            const token = jwt.sign({ id }, process.env.SECRET, {expiresIn: '20m'});
            sendEmail(emailId, true, token, (err) => {
                if(err){
                    return res.status(500).json({
                        error: err
                    })
                }else{
                    return res.status(200).json({
                        message: "reset password link has been sent to your registered mail Id"
                    })
                }
            })
        }
    })
};

// Method for updating the password
exports.updatePass = (req, res) => {
    const {token, password} = req.body;
    if(token){
        jwt.verify(token, process.env.SECRET,(err,decodedToken) =>{
            if(err){
                return res.status(400).json({
                    error: "Link Expired"
                });
            }
            const {id} = decodedToken;
            User.findById(id, (err, user) => {
                if(err) {
                    return res.status(500).json({
                        error: "unable to update password"
                    });
                }
                user.password = password;
                user.save((err,user) => {
                    if(err){
                        return res.status(400).json({
                            error:"Unable to update password"
                        })
                    }
                    return res.status(200).json({
                        message: `password updated`
                    });
                });
            });
        });
    } else{
        return res.status(500).json({
            error: "unauthorized request"
        })
    }
};