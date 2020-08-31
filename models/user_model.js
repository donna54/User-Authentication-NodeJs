// Imports
const mongoose = require('mongoose');
const Schema = mongoose.Schema
const bcrypt = require('bcryptjs')


// Defining user schema
const userSchema = new Schema({
    emailId: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    name: {
        type: String,
        required: true
    },
    emailConfirmation: {
        type: Boolean,
        default: false
    },
    salt: {
        type: String
    }
}, { TimeStamp: true });


userSchema.methods = {
    // Method to check credentials
    authenticate: function (plainpassword, storedpassword) {
        try {
            const match = bcrypt.compare(plainpassword, storedpassword);
            if (match) {
                return true
            } else {
                return false
            }
        } catch (error) {
            throw new Error('Hashing failed', error)
        }
    }
};

module.exports = mongoose.model('User', userSchema);