const express = require('express');
const MongoClient = require('mongodb').MongoClient;
const path = require('path'); // Import the 'path' module
const { Script } = require('vm');
const multer = require('multer');
const session = require('express-session');
const nodemailer = require('nodemailer');
const fs = require('fs');
const otpGenerator = require('otp-generator');
const ObjectId = require('mongodb').ObjectId;
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: 'lendingmanangement@gmail.com',
      pass: 'hizuotzzduxyelya'
    }
  });

const app = express();
const PORT = process.env.PORT || 8080;

const connectionString = 'mongodb+srv://akosijaycee:Eyeshield232045@cluster0.rb77oza.mongodb.net/';
const client = new MongoClient(connectionString, { useNewUrlParser: true, useUnifiedTopology: true });
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.use(
    session({
        secret: 'ebong', // Replace with your own secret key
        resave: false,
        saveUninitialized: true
    })
);

app.use(express.static(__dirname));
app.use(express.json());

app.get('/', (req, res) => {
    const filePath = path.join(__dirname, 'index.html');
    res.sendFile(filePath);
});

// START OF THE SERVER REGISTER //

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        await client.connect();
        const db = client.db('users');
        const usersCollection = db.collection('theiruserandpass');

        // Check if the username already exists
        const existingUsername = await usersCollection.findOne({ username });

        if (existingUsername) {
            res.status(409).json({ message: 'Username already exists' });
            return;
        }

        // Check if the email already exists
        const existingEmail = await usersCollection.findOne({ email });

        if (existingEmail) {
            res.status(409).json({ message: 'Email already exists' });
            return;
        }

        // Generate OTP
        const otp = otpGenerator.generate(6, { digits: true, alphabets: false, upperCase: false, specialChars: false });
        // If both username and email are unique, proceed with registration
        const newUser = {
            username,
            email,
            password, // Remember to hash and salt the password before storing it
            "account-status": 'unverified', // Set account status to "unverified"
            otp
        };

        const result = await usersCollection.insertOne(newUser);

        const mailOptions = {
            from: 'LMS', // Replace with your email address
            to: email, // Use the email provided in the registration form
            subject: 'Account Verification OTP',
            text: `Your OTP: ${otp}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log('Error sending email:', error);
            } else {
                console.log('Email sent:', info.response);
            }
        });

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});


// END OF THE SERVER REGISTER//


// START OF THE SERVER LOGIN//
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        await client.connect();
        const db = client.db('users');
        const usersCollection = db.collection('theiruserandpass');

        const user = await usersCollection.findOne({ email });

        if (!user) {
            res.status(401).json({ message: 'Invalid credentials' });
            return;
        }

        if (user.password !== password) {
            res.status(401).json({ message: 'Invalid credentials' });
            return;
        }

        if (user['account-status'] === 'unverified') {
            res.status(401).json({ message: 'Please verify your account first' });
            return;
        }

        // If everything is correct, log in the user
        req.session.username = user.username; // Store the username in the session

        res.status(200).json({ message: 'Login successful' , userId:user._id});

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// END OF THE SERVER FOR LOGIN //

// START OF THE SERVER FOR APPLICATION //

app.post('/submitLoanApplication', upload.single('photo'), async (req, res) => {
    const formData = req.body;
    const photo = req.file; // The uploaded photo data
    const status = 'Pending'; // Set the default status to "Pending"
    const username = req.session.username || 'Guest'; // Retrieve the username from the session

    // Read the binary data of the image file
    const capturedPhotoPath = 'D:/ALL/website/images/questionmark.png'; // Provide the correct file path
    let capturedPhotoData;

    try {
        capturedPhotoData = fs.readFileSync(capturedPhotoPath);
    } catch (error) {
        console.error('Error reading the image file:', error);
        res.status(500).json({ message: 'Failed to submit loan application' });
        return;
    }

    try {
        await client.connect();
        const db = client.db('users'); // Use the correct database name
        const usersLoanCollection = db.collection('usersloan'); // Use the correct collection name

        const newLoanApplication = {
            ...formData,
            photo: {
                originalname: photo.originalname,
                mimetype: photo.mimetype,
                size: photo.size,
                data: photo.buffer // Store the file content as a Buffer
            },
            capturedPhoto: capturedPhotoData, // Store the image binary data
            status: status, // Set the default status
            username: username // Add the username to the loan application
        };

        const result = await usersLoanCollection.insertOne(newLoanApplication);
        res.status(201).json({ message: 'Loan application submitted successfully' });
    } catch (error) {
        console.error('Error submitting loan application:', error);
        res.status(500).json({ message: 'Failed to submit loan application' });
    }
});




// END OF THE APPLICATION //

app.get('/getLoanApplications', async (req, res) => {
    try {
        await client.connect();
        const db = client.db('users'); // Use the correct database name
        const usersLoanCollection = db.collection('usersloan'); // Use the correct collection name

        const username = req.session.username || ''; // Retrieve the username from the session
        const loanApplications = await usersLoanCollection.find({ username }).toArray();
        res.status(200).json(loanApplications);
    } catch (error) {
        console.error('Error getting loan applications:', error);
        res.status(500).json({ message: 'Failed to get loan applications' });
    }
});

app.get('/getPaymentSchedules', async (req, res) => {
    try {
        await client.connect();
        const db = client.db('users'); // Use the correct database name
        const paymentSchedulesCollection = db.collection('userspaymentschedules'); // Use the correct collection name

        const username = req.session.username || ''; // Retrieve the username from the session
        const paymentSchedules = await paymentSchedulesCollection.find({ username }).toArray();
        res.status(200).json(paymentSchedules);
    } catch (error) {
        console.error('Error getting payment schedules:', error);
        res.status(500).json({ message: 'Failed to get payment schedules' });
    }
});




app.post('/changePassword', async (req, res) => {
    const username = req.session.username;
    const oldPassword = req.body['old-password'];
    const newPassword = req.body['new-password'];
    const confirmPassword = req.body['confirm-password'];
  
    try {
      // Connect to MongoDB and retrieve user data by username
      await client.connect();
      const db = client.db('users');
      const usersCollection = db.collection('theiruserandpass'); // Use the correct collection name
      const user = await usersCollection.findOne({ username });
  
      if (!user || user.password !== oldPassword) {
        // Invalid old password
        return res.status(400).json({ message: 'Invalid old password' });
      }
  
      if (newPassword !== confirmPassword) {
        // New password and confirm password do not match
        return res.status(400).json({ message: 'New password and confirm password do not match' });
      }
  
      // Update user's password in the collection
      await usersCollection.updateOne({ username }, { $set: { password: newPassword } });
  
      res.status(200).json({ message: 'Password changed successfully' });
    } catch (error) {
      console.error('Error changing password:', error);
      res.status(500).json({ message: 'Failed to change password' });
    }
  });

  app.post('/verify', async (req, res) => {
    const { email, otp } = req.body;


    console.log('Received email:', email);
    console.log('Received OTP:', otp);

    try {
        await client.connect();
        const db = client.db('users');
        const usersCollection = db.collection('theiruserandpass');

        const user = await usersCollection.findOne({ email, otp });

        if (user) {
            // Update the account status to "verified" and remove OTP
            await usersCollection.updateOne(
                { _id: user._id },
                { $set: { "account-status": "verified" }, $unset: { otp: "" } }
            );
            return res.send('Your account has been verified. You can now log in.');
            
        } else {
            console.log('Invalid OTP or email');
            return res.send('Invalid OTP or email.');
        }
    } catch (error) {
        console.error('Error verifying account:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/forgot', async (req, res) => {
    const { email } = req.body;

    try {
        await client.connect();
        const db = client.db('users');
        const usersCollection = db.collection('theiruserandpass');

        const user = await usersCollection.findOne({ email });

        if (!user) {
            return res.send('This email is not valid.');
        } else if (user["account-status"] !== "verified") {
            return res.send('This email is not verified.');
        } else {
            const otp = otpGenerator.generate(6, { digits: true, alphabets: false, upperCase: false, specialChars: false });

            // Store the OTP in the user's document
            await usersCollection.updateOne(
                { _id: user._id },
                { $set: { otp: otp } }
            );

            const mailOptions = {
                from: 'LMS', // Replace with your email address
                to: email, // Use the email provided in the registration form
                subject: 'Account Verification OTP',
                text: `Your OTP: ${otp}`
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.log('Error sending email:', error);
                } else {
                    console.log('Email sent:', info.response);
                }
            });


            return res.send('Check your email for OTP instructions.');
        }
    } catch (error) {
        console.error('Error in forgot password:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/verifyOTP', async (req, res) => {
    const { email, otp } = req.body;

    try {
        await client.connect();
        const db = client.db('users');
        const usersCollection = db.collection('theiruserandpass');

        const user = await usersCollection.findOne({ email });

        if (user && user.otp === otp) {
            // Remove the OTP from the user's document
            await usersCollection.updateOne(
                { _id: user._id },
                { $unset: { otp: "" } }
            );

            // Proceed to the next form for password reset
            return res.send('OTP verified. Proceed to password reset.');
        } else {
            return res.send('Invalid OTP.');
        }
    } catch (error) {
        console.error('Error verifying OTP:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/reset', async (req, res) => {
    const { email, newPassword } = req.body;

    try {
        await client.connect();
        const db = client.db('users');
        const usersCollection = db.collection('theiruserandpass');

        // Find the user by email
        const user = await usersCollection.findOne({ email });

        if (!user) {
            return res.send('Email not found');
        }

        // Update the user's password with the new password
        await usersCollection.updateOne(
            { _id: user._id },
            { $set: { password: newPassword } }
        );

        return res.send('Password reset successful');
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/getUserData', async (req, res) => {
    const { username } = req.query;

    try {
        // Connect to MongoDB and retrieve user data by username
        await client.connect();
        const db = client.db('users');
        const usersCollection = db.collection('theiruserandpass'); // Use the correct collection name
        const user = await usersCollection.findOne({ username });

        if (!user) {
            res.status(404).json({ message: 'User not found' });
            return;
        }

        // Respond with the user data (excluding sensitive information like password)
        const userData = {
            userID: user._id,
            email: user.email,
            accountStatus: user['account-status'],
            profilePicture: user.profilePicture || null
        };

        res.status(200).json(userData);
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


app.get('/getLoanDetails', async (req, res) => {
    const { username } = req.query;

    try {
        // Connect to MongoDB and retrieve user data by username
        await client.connect();
        const db = client.db('users');
        const usersCollection = db.collection('usersloan'); // Use the correct collection name
        const loanDetails = await usersCollection.find({ username, status: { $in: ['Active', 'Pending', 'Approved'] } }).toArray();

        if (!loanDetails || loanDetails.length === 0) {
            res.status(404).json({ message: 'Loan details not found' });
        } else {
            res.status(200).json(loanDetails);
        }

        client.close();
    } catch (error) {
        console.error('Error fetching loan details:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


app.get('/checkLoanStatus', async (req, res) => {
    // We retrieve the username from the session or set it to 'Guest' if not available.
    const username = req.session.username || 'Guest';

    try {
        // Establish a database connection and select the appropriate collection.
        await client.connect();
        const db = client.db('users'); // Replace 'users' with your actual database name
        const usersLoanCollection = db.collection('usersloan'); // Replace 'usersloan' with your actual collection name

        // Check if the user already has an active loan or pending application in the database.
        const existingLoan = await usersLoanCollection.findOne({
            username,
            status: { $in: ['Pending', 'Approved', 'Active'] }
        });

        // Determine if the user can apply for a new loan based on the existing loan status.
        const canApply = !existingLoan || existingLoan.status === 'Closed';

        // Send the result back to the client as JSON.
        res.status(200).json({ canApply });
    } catch (error) {
        console.error('Error checking loan status:', error);
        // In case of an error, return an error response to the client.
        res.status(500).json({ message: 'Failed to check loan status' });
    }
});




app.get('/getClosedLoans', async (req, res) => {
    try {
        await client.connect();
        const db = client.db('users'); // Use the correct database name
        const usersLoanCollection = db.collection('usersloan'); // Use the correct collection name

        const username = req.session.username || ''; // Retrieve the username from the session

        // Fetch closed loans based on a specific status (e.g., 'Closed')
        const closedLoans = await usersLoanCollection.find({ username, status: 'Closed' }).toArray();
        
        res.status(200).json(closedLoans);
    } catch (error) {
        console.error('Error getting closed loans:', error);
        res.status(500).json({ message: 'Failed to get closed loans' });
    }
});

app.get('/getRejectedLoans', async (req, res) => {
    try {
        await client.connect();
        const db = client.db('users'); // Use the correct database name
        const usersLoanCollection = db.collection('usersloan'); // Use the correct collection name

        const username = req.session.username || ''; // Retrieve the username from the session

        // Fetch closed loans based on a specific status (e.g., 'Closed')
        const rejectedLoans = await usersLoanCollection.find({ username, status: 'Rejected' }).toArray();
        
        res.status(200).json(rejectedLoans);
    } catch (error) {
        console.error('Error getting Rejected loans:', error);
        res.status(500).json({ message: 'Failed to get Rejected loans' });
    }
});



app.post('/saveProfilePicture', upload.single('profileImage'), async (req, res) => {
    const username = req.session.username; // Get the username from the session

    if (!username) {
        // User is not logged in
        res.status(401).json({ message: 'Unauthorized' });
        return;
    }

    const file = req.file; // Uploaded file
    if (!file) {
        // No file provided
        res.status(400).json({ message: 'No file uploaded' });
        return;
    }

    try {
        // Store the profile picture in MongoDB
        await client.connect();
        const db = client.db('users');
        const usersCollection = db.collection('theiruserandpass');

        // Find the user by username and update their profile picture
        await usersCollection.updateOne(
            { username },
            { $set: { profilePicture: file.buffer.toString('base64') } }
        );

        res.status(200).json({ message: 'Profile picture saved successfully' });
    } catch (error) {
        console.error('Error saving profile picture:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});






app.get('/getUsername', (req, res) => {
    const username = req.session.username || 'Guest';
    res.json({ username });
});

app.get('/apply', (req, res) => {
    const username = req.session.username || 'Guest';
    res.json({ username });
});

app.get('/account', (req, res) => {
    const username = req.session.username || 'Guest';
    res.json({ username });
});


