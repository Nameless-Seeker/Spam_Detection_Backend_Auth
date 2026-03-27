import express from "express"
import mongoose from "mongoose";
import * as dotenv from "dotenv";
import jwt from "jsonwebtoken"
import User from "./user.js";

dotenv.config();
const app = express()

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log("DB connected")
    })
    .catch((err) => {
        console.log("DB not connected")
    })

// For extracting body
app.use(express.json())


app.get("/", (req, res) => {
    res.send("Everything is going to be ok :)")
})

//Tokens
function generateAccessToken(user) {
    return jwt.sign(
        { username: user.username },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "15m" }
    );
}

function generateRefreshToken(user) {
    return jwt.sign(
        { username: user.username },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: "7d" }
    );
}

function authenticateToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({
            message: "Access token missing"
        })
    }

    jwt.verify(
        token,
        process.env.ACCESS_TOKEN_SECRET,
        (err, user) => {

            if (err) {
                return res.status(401).json({
                    message: "Invalid or expired token"
                })
            }

            req.user = user
            next()
        }
    )
}

//SIGN UP
app.post('/signup', async (req, res, next) => {
    const {username, password} = req.body;

    if (!username || !password) {
        return res.status(400).json({message: "Username and password are required"});
    }

    try {
        // Find a user with the EXACT password
        const existingUser = await User.findOne({password: password});

        if (existingUser) {
            // "If it matches, then, Do not signup."
            return res.status(409).json({message: "Account with this password already exists."});
        } else {
            // "If it does not, then add a document like this"
            const newUser = new User({
                username: username,
                password: password,
                listOfContacts: [] // Initialized as an empty array
            });

            await newUser.save();
            return res.status(201).json({
                message: "Signup successful"
            });
        }
    } catch (error) {
        return res.status(500).json({message: "Server error", error: error.message});
    }
});

//Login endpoint
app.post('/login', async (req, res) => {
    const {username, password} = req.body;

    // 1. Verify that both fields were provided
    if (!username || !password) {
        return res.status(400).json({message: "Username and password are required"});
    }

    try {
        // 2. Look for a user with this exact username AND password
        const user = await User.findOne({username: username, password: password});

        // 3. If no user is found, the credentials don't match
        if (!user) {
            return res.status(401).json({message: "Invalid username or password"});
        }
        
        //generate tokens
        const accessToken = generateAccessToken(user)
        const refreshToken = generateRefreshToken(user)

        // 4. If a user is found, login is successful
        return res.status(200).json({
            accessToken: accessToken,
            refreshToken: refreshToken,
            user: {
                username: user.username,
                phone_number: user.password,
                listOfContacts: user.listOfContacts // Returning the user's nested listOfContacts
            }
            // Note: We purposely leave the password out of the response
            // so it doesn't get sent back to the frontend unnecessarily.
        });

    } catch (error) {
        return res.status(500).json({message: "Server error", error: error.message});
    }
});

// Refresh
app.post("/refresh", (req, res) => {

    const { refreshToken } = req.body

    if (!refreshToken) {
        return res.status(401).json({
            message: "Refresh token missing"
        })
    }

    try {

        const decoded = jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )

        const user = { username: decoded.username }

        const newAccessToken = jwt.sign(
            user,
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "15m" }
        )

        const newRefreshToken = jwt.sign(
            user,
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: "7d" }
        )

        return res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        })

    } catch (error) {

        return res.status(403).json({
            message: "Invalid refresh token",
            error: error
        })

    }

})


//add-contacts
app.post('/add-contact', authenticateToken,async (req, res) => {
    const {password, contactUsername, contactPassword } = req.body;

    // 1. Ensure all four fields are provided
    if (!password || !contactUsername || !contactPassword) {
        return res.status(400).json({
            message: "Missing fields. Provide your username/password and the contact's username/password."
        });
    }

    try {
        // 2. "The server checks if I am there or not."
        const user = await User.findOne({password: password });
        if (!user) {
            return res.status(401).json({ message: "Unauthorized: Your account was not found." });
        }

        // 3. "If I am there then it checks if that new person is in the database or not by checking both username and password."
        const contactUser = await User.findOne({ password: contactPassword });
        if (!contactUser) {
            return res.status(404).json({ message: "The user you are trying to add does not exist." });
        }

        // 4. "If that person's name is there, then check if that person is already in my listOfContacts' list."
        // We use the JavaScript .some() method to see if any existing contact matches the username
        const isAlreadyContact = user.listOfContacts.some(
            (contact) => contact.username === contactUsername
        );

        if (isAlreadyContact) {
            return res.status(409).json({ message: "This person is already in your contacts list." });
        }

        // 5. "If that person is not there, then, add that person to my listOfContacts."
        user.listOfContacts.push({
            username: contactUser.username,
            password: contactUser.password
        });

        await user.save();

        return res.status(200).json({
            message: "Contact added successfully!",
            listOfContacts: user.listOfContacts
        });

    } catch (error) {
        return res.status(500).json({ message: "Server error", error: error.message });
    }
});

// DELETE CONTACT
app.post('/delete-contact', authenticateToken,async (req, res) => {

    const { password, contactPassword } = req.body;

    // 1️⃣ Ensure required fields
    if (!password || !contactPassword) {
        return res.status(400).json({
            message: "Both your password and contact password are required."
        });
    }

    try {

        // 2️⃣ Check if my account exists
        const user = await User.findOne({ password: password });

        if (!user) {
            return res.status(401).json({
                message: "Your account was not found."
            });
        }

        // 3️⃣ Check if contact exists in database
        const contactUser = await User.findOne({ password: contactPassword });

        if (!contactUser) {
            return res.status(404).json({
                message: "The contact you are trying to delete does not exist."
            });
        }

        // 4️⃣ Check if the contact exists inside my listOfContacts
        const index = user.listOfContacts.findIndex(
            contact => contact.password === contactPassword
        );

        if (index === -1) {
            return res.status(404).json({
                message: "This contact is not in your contact list."
            });
        }

        // 5️⃣ Remove the contact
        user.listOfContacts.splice(index, 1);

        await user.save();

        // 6️⃣ Return updated list
        return res.status(200).json({
            message: "Contact deleted successfully",
            listOfContacts: user.listOfContacts
        });

    } catch (error) {

        return res.status(500).json({
            message: "Server error",
            error: error.message
        });

    }

});

// Get Contacts endpoint
app.post('/get-contacts',authenticateToken, async (req, res) => {
    const { password } = req.body; // In your app, this is the phone number

    // 1. Ensure the password was provided
    if (!password) {
        return res.status(400).json({ message: "Password is required to fetch contacts." });
    }

    try {
        // 2. Find the user in the database using just the password
        const user = await User.findOne({ password: password });

        // 3. If no user is found, return a 404 error
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        // 4. Return their list of contacts!
        return res.status(200).json({
            message: "Contacts retrieved successfully",
            listOfContacts: user.listOfContacts
        });

    } catch (error) {
        return res.status(500).json({ message: "Server error", error: error.message });
    }
});


// GET FLAGS
app.post('/get-flags', authenticateToken, async (req, res) => {

    const { password } = req.body

    if (!password) {
        return res.status(400).json({
            message: "Password is required"
        })
    }

    try {

        const user = await User.findOne({ password: password })

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        }

        return res.status(200).json({
            flags: user.flag
        })

    } catch (error) {

        return res.status(500).json({
            message: "Server error",
            error: error.message
        })

    }

})

app.post('/increase-flag', authenticateToken, async (req, res) => {

    const { password } = req.body

    try {

        const user = await User.findOneAndUpdate(
            { password: password },
            { $inc: { flag: 1 } },
            { new: true }
        )

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        }

        return res.status(200).json({
            message: "Flag increased",
        })

    } catch (error) {

        return res.status(500).json({
            message: "Server error",
            error: error.message
        })

    }

})


// Error Handler
app.use((err, req, res, next) => {
    const statusCode = err.status || 500
    const message = err.message || "Something went wrong"

    return res.status(statusCode).json({message: message})
})


const PORT = 3000;

app.listen(PORT, () => {
    console.log(`Server is running in ${PORT}`)
})


//     [{
//     username: "A",
//     password: "B",
//     listOfContacts: [{username: "C", password: "D"}, {username: "E", password: "F"}]
// },
//     {
//         username: "C",
//         password: "D",
//         listOfContacts: [{username: "A", password: "B"}, {username: "Y", password: "Z"}]
//     }
//     ]
//
// {
//     username: "S",
//         password
// :
//     "T",
//         listOfContacts
// :
//     []
// }



