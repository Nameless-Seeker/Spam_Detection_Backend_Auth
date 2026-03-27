const mongoose = require('mongoose');

// Define the structure you requested
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    listOfContacts: [{
        username: { type: String },
        password: { type: String }
    }],
    flag: Number
});

const User = mongoose.model('User', userSchema);
module.exports = User;