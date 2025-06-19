const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'your_jwt_secret'; // Use a more secure method for secrets

app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/unusedItemsExchange', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB Connected'))
  .catch((err) => console.log('MongoDB Connection Error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    username: String,
    phone: { type: String, unique: true },
    email: String,
    password: String,
});

// Hash password before saving user
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
    next();
});

const User = mongoose.model('User', userSchema);

// Signup Route
app.post('/signup', async (req, res) => {
    const { username, phone, email, password } = req.body;
    
    const userExists = await User.findOne({ phone });
    if (userExists) {
        return res.status(400).json({ message: 'User already exists with this phone number' });
    }
    
    const newUser = new User({
        username,
        phone,
        email,
        password
    });
    
    await newUser.save();
    res.status(201).json({ message: 'User created successfully' });
});

// Login Route
app.post('/login', async (req, res) => {
    const { phone, password } = req.body;
    
    const user = await User.findOne({ phone });
    if (!user) {
        return res.status(400).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
        message: 'Login successful',
        token,
        user: {
            username: user.username,
            phone: user.phone,
            email: user.email
        }
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
