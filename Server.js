require('dotenv').config()
const express = require('express')
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const mongoose = require('mongoose');
const app = express();
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt =require('bcrypt');


app.use(cors());
app.use(bodyParser.json())


//connecting to mongodb
const url = process.env.MONGODB_URL;

mongoose.connect(url)
.then(()=>{
    console.log("connected to mongodb");
})
.catch(err =>{
    console.log(err);
})

const User= mongoose.model('User',{
    email: String,
    resetToken: String,
    tokenExpiry: Date,
})


app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password before saving it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create and save the user
    const newUser = new User({
      email,
      password: hashedPassword,
    });
    await newUser.save();

    return res.json({ message: 'Registration successful' });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ message: 'Database error' });
  }
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    // Compare the provided password with the stored hashed password
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Incorrect password' });
    }

    // Passwords match, user is authenticated
    return res.json({ message: 'Login successful' });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ message: 'Database error' });
  }
});



app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
  
    try {
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.json({ message: 'User not found' });
      }
  
      const token = crypto.randomBytes(32).toString('hex');
      const tokenExpiry = Date.now() + 3600000; // Token valid for 1 hour
  
      user.resetToken = token;
      user.tokenExpiry = tokenExpiry;
      await user.save();
  
      const transporter = nodemailer.createTransport({
        service: process.env.EMAIL_SERVICE_PROVIDER,
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.GMAIL_APP_PASSWORD,
        },
      });
  
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset',
        text: `Click the following link to reset your password: https://strong-crostata-9401e0.netlify.app/reset-password/${token}`,
      };
  
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
          return res.status(500).json({ message: 'Error sending email' });
        }
        console.log('Email sent:', info.response);
        return res.json({ message: 'Password reset link sent to your email' });
      });
    } catch (error) {
      console.error('Database error:', error);
      res.status(500).json({ message: 'Database error' });
    }
  });

  //resetToken 
  app.get('/reset-token/:token', async (req, res) => {
    const { token } = req.params;
  
    try {
      const user = await User.findOne({
        resetToken: token,
        tokenExpiry: { $gt: Date.now() },
      });
  
      if (!user) {
        return res.json({ tokenValid: false });
      }
  
      return res.json({ tokenValid: true });
    } catch (error) {
      console.error('Database error:', error);
      res.status(500).json({ message: 'Database error' });
    }
  });
  
  //to reset the password
  app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
  
    try {
      const user = await User.findOne({
        resetToken: token,
        tokenExpiry: { $gt: Date.now() },
      });
  
      if (!user) {
        return res.json({ message: 'Invalid or expired token' });
      }

      //hashing the nw password before saving it
      const hashedPassword = await bcrypt.hash(password, 10);
  
      user.password = hashedPassword; // Update the user's password
      user.resetToken = undefined;
      user.tokenExpiry = undefined;
      await user.save();
  
      return res.json({ message: 'Password updated successfully' });
    } catch (error) {
      console.error('Database error:', error);
      res.status(500).json({ message: 'Database error' });
    }
  });
  

const PORT =3001;
app.listen(PORT,()=>{
    console.log(`Server connected to PORT ${PORT}`)
})
