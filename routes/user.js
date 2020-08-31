// Imports
const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const controller = require('../controllers/user_controller');

router.route('/register')
    .get((req,res) => {
        res.render('register')
    })
    .post([
        check('emailId').isEmail().isLength({min: 10, max: 30}),
        check('name').isLength({min: 10, max: 20}),
        check('password', 'Password length should be 8 to 10 characters') 
                    .isLength({ min: 8, max: 10 })
    ],async (req, res, next) => controller.signup(req, res, next))

// Signin
router.post('/signin', controller.signin);

// Verify emailId for registration
router.post("/emailVerification", controller.emailactivate);

// Resend Activation Mail
router.post("/resendActivation", controller.resendActivation);

// Signout
router.get("/signout", controller.signout);

// Resetting the password
router.post("/resetpassword", controller.resetpass);

// Updating password
router.post("/updatepassword", controller.updatePass);

module.exports = router;