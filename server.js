import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import FormData from "form-data"; 
import Mailgun from "mailgun.js"; 
import dotenv from 'dotenv';
import Stripe from 'stripe';

dotenv.config();
const stripe = Stripe(process.env.STRIPE_SECRET);

const app = express();
app.use(cookieParser()); 
app.use(cors({
  origin: 'https://depaulclimbing.com', // frontend origin, need to change to url after deployment
  credentials: true
}));

// const db = mysql.createConnection({
//     host: 'localhost',
//     user: 'root',
//     password: '',
//     database: 'test'
// })

const db = mysql.createConnection({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT
});

app.get('/', (re, res)=> {
    return res.json('From backend side');
})

app.post('/webhook', express.raw({ type: "application/json" }), (req, res) => {
    res.sendStatus(200);
    const sig = req.headers["stripe-signature"];

    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error("Webhook signature verification failed.", err.message);
        return res.sendStatus(400);
    }

    if (event.type === "checkout.session.completed") {
        const session = event.data.object;

        // Retrieve metadata if you store passes + email in session
        const email = 'santos@depaul.edu' // session.metadata.email;
        const passes = 1 // session.metadata.passes;
        const type = 'passes' // session.metadata.type;
    console.log(email, passes, type);

    try {
      if (type === "dues") {
        // Update database: mark dues as paid
        db.query(
          "UPDATE users SET Dues = 1 WHERE Email = ?",
          [email]
        );
        console.log(`✅ Dues paid for ${email}`);
      } else if (type === "passes") {
        // Update database: increment passes
        db.query(
          "UPDATE users SET Passes = Passes + ? WHERE Email = ?",
          [passes, email]
        );
        console.log(`✅ Added ${passes} passes for ${email}`);
      }
    } catch (dbErr) {
      console.error("Database update failed:", dbErr);
    }
  }
    res.json({ received: true });
});

app.use(express.json());

app.get('/refresh', (req, res) => {
    const refreshToken = req.cookies?.refreshToken;
    if (!refreshToken) return res.status(401).json({ message: 'No refresh token provided' });

    jwt.verify(refreshToken, 'your_refresh_token_secret', (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Invalid refresh token' });

        // Get user data from database
        const sql = "SELECT * FROM users WHERE Email = ?";
        db.query(sql, [decoded.email], (err, results) => {
            if (err) return res.status(500).json({ message: 'Server error' });
            if (results.length === 0) return res.status(404).json({ message: 'User not found' });

            const dbUser = results[0];

            // Generate new access token
            const accessToken = jwt.sign(
                { email: dbUser.Email, role: dbUser.Role },
                'your_access_token_secret',
                { expiresIn: '15m' }
            );

            // Exclude password from response
            const { Password, ...userData } = dbUser;

            res.json({ 
                accessToken,
                roles: [dbUser.Role], // Array format to match your frontend expectations
                user: userData
            });
        });
    });
});

app.get('/users', (req, res)=> {
    const sql = 'SELECT * FROM users'
    db.query(sql, (err, data)=> {
        if(err) return res.json(err);
        return res.json(data);
    })
})

app.get('/check-ins', (req, res) => {
    const sql = 'SELECT * FROM `check-ins` ORDER BY DateTime DESC';
    db.query(sql, (err, results) => {
        if (err) return res.json(err);
        return res.json(results);
    });
})

app.listen(3000, ()=> {
    console.log('Server listening');
   })

app.post('/auth', (req, res) => {
    const { user, pwd } = req.body;
    const sql = "SELECT * FROM users WHERE Email = ?";
    db.query(sql, [user], (err, results) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        if (results.length === 0) return res.status(401).json({ message: 'Email not found' });

        const dbUser = results[0];
        bcrypt.compare(pwd, dbUser.Password, (err, result) => {
            if (err) return res.status(500).json({ message: 'Server error' });
            if (!result) return res.status(401).json({ message: 'Incorrect password' });

            // Generate access token
            const accessToken = jwt.sign(
                { email: dbUser.Email, role: dbUser.Role },
                'your_access_token_secret',
                { expiresIn: '15m' }
            );

            // Generate refresh token
            const refreshToken = jwt.sign(
                { email: dbUser.Email, role: dbUser.Role },
                'your_refresh_token_secret',
                { expiresIn: '7d' }
            );

            // Set refresh token as HTTP-only cookie
            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: false, // set to true in production (HTTPS)
                sameSite: 'Strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
                path: '/'
            });

            // Exclude password from response
            const { Password, ...userData } = dbUser;
            return res.json({ user: userData, accessToken });
        });
    });
});

app.post('/logout', (req, res) => {
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: false, // set to true in production (HTTPS)
        sameSite: 'Strict',
        path: '/'
    });
    return res.json({ message: 'Logged out successfully' });
});

app.post('/register', (req, res) => {
    const { email, pwd, firstName, lastName } = req.body;
    console.log(email, pwd, firstName, lastName);
        // Hash password and insert new user
        bcrypt.hash(pwd, 10, (err, hash) => {
            if (err) return res.status(500).json({ message: 'Server error' });

            const insertSql = "INSERT INTO users (Email, First, Last, Password, Passes, Role, Dues) VALUES (?, ?, ?, ?, ?, ?, ?)";
            db.query(insertSql, [email, firstName, lastName, hash, 0, 2001, 0], (err, result) => {
                if (err) return res.status(500).json({ message: 'Server error' });
                return res.status(201).json({ message: 'User registered' });
            });
        });
    });

app.post('/use-pass', (req, res) => {
    const { firstName, lastName, email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email not found' });

    const now = new Date();
    const cstDate = new Date(now.toLocaleString("en-US", {timeZone: "America/Chicago"}));
    
    // Format as YYYY-MM-DD HH:MM:SS for MySQL
    const currentDateTime = cstDate.getFullYear() + '-' +
        String(cstDate.getMonth() + 1).padStart(2, '0') + '-' +
        String(cstDate.getDate()).padStart(2, '0') + ' ' +
        String(cstDate.getHours()).padStart(2, '0') + ':' +
        String(cstDate.getMinutes()).padStart(2, '0') + ':' +
        String(cstDate.getSeconds()).padStart(2, '0');

    console.log(currentDateTime); // Will output: 2025-08-05 19:48:42

    const useSql = 'UPDATE users SET Passes = Passes - 1 WHERE Email = ? AND Passes > 0';
    db.query(useSql, [email], (err, result) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found' });


        const insertSql = "INSERT INTO `check-ins` (First, Last, Email, DateTime) VALUES (?, ?, ?, ?)";
        db.query(insertSql, [firstName, lastName, email, currentDateTime], (err, result) => {
            if (err) return res.status(500).json({ message: 'Server error' });
            return res.status(200).json({ 
                message: 'Pass used and check-in recorded',
                dateTime: currentDateTime});
        });

    });

});

app.post('/purchase-passes', async (req, res) => {
    const { email, passes, price } = req.body;

    try {
        // Create Stripe Checkout Session
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            mode: "payment",
            line_items: [
                {
                    price_data: {
                        currency: "usd",
                        product_data: {
                            name: `${passes} Climbing Pass(es)`
                        },
                        unit_amount: Math.round(price * 100), // Stripe wants cents
                    },
                    quantity: 1,
                },
            ],
            success_url: "http://localhost:5173/success",
            cancel_url: "http://localhost:5173/cancel",
            metadata: { email, passes, type: "passes" },
        });

        // Save pending purchase (optional, for audit log)
        // You can also update after payment succeeds via webhook (safer).
        
        res.json({ id: session.id });
    } catch (error) {
        console.error("Error creating checkout session:", error);
        res.status(500).json({ error: "Unable to create checkout session" });
    }
});

// need to update dues in db after successful payment
app.post('/purchase-dues', async (req, res) => {
    const { email, price } = req.body;

    const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [
            {
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: 'Membership Dues',
                    },
                    unit_amount: Math.round(price * 100), // Convert to cents
                },
                quantity: 1,
            }
        ],
        mode: 'payment',
        success_url: 'http://localhost:5173/success',
        cancel_url: 'http://localhost:5173/cancel',
        metadata: { email, type:"dues" },
    })

    res.json({ id: session.id });
});

async function sendVerificationEmail(recipient_email, OTP) {
  const mailgun = new Mailgun(FormData);
  const mg = mailgun.client({
    username: "api",
    key: process.env.MAILGUN_API,
  });
    try {
        const data = await mg.messages.create("depaulclimbing.com", {
        from: "DePaul Climbing <noreply@depaulclimbing.com>",
        to: recipient_email,
        subject: "DePaul Climbing Verification Code",
        html:`<!DOCTYPE html>
            <html lang="en" >
            <head>
            <meta charset="UTF-8">
            <title>DePaul Climbing - OTP Email Template</title>


            </head>
            <body>
            <!-- partial:index.partial.html -->
            <div style="font-family: Helvetica,Arial,sans-serif;min-width:1000px;overflow:auto;line-height:2">
            <div style="margin:50px auto;width:70%;padding:20px 0">
                <div style="border-bottom:1px solid #eee">
                <a href="" style="font-size:1.4em;color: #00466a;text-decoration:none;font-weight:600">DePaul Climbing</a>
                </div>
                <p style="font-size:1.1em">Hi,</p>
                <p>Use the following code to complete verification. OTP is valid for 5 minutes</p>
                <h2 style="background: #00466a;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;">${OTP}</h2>
                <p style="font-size:0.9em;">Regards,<br />DePaul Climbing</p>
                <hr style="border:none;border-top:1px solid #eee" />
            </div>
            </div>
            <!-- partial -->
            
            </body>
            </html>`,
        });

        console.log(data); // logs response data
        return data;
    } catch (error) {
        console.log(error); //logs any error
    }
};

app.post('/send-recovery-email', (req, res) => {
    const { recipient_email, pwd, firstName, lastName, OTP } = req.body;
    console.log(recipient_email, pwd, firstName, lastName, OTP);

    if (!firstName) {
        const checkSql = "SELECT * FROM users WHERE Email = ?";
        db.query(checkSql, [recipient_email], (err, results) => {
            if (err) return res.status(500).json({ message: 'Server error' });
            if (results.length === 0) return res.status(404).json({ message: 'No account with this email' });
    });
    } else {
        if (!recipient_email || !pwd) return res.status(400).json({ message: 'Email and password required' });

        const checkSql = "SELECT * FROM users WHERE Email = ?";
        db.query(checkSql, [recipient_email], (err, results) => {
            if (err) return res.status(500).json({ message: 'Server error' });
            if (results.length > 0) return res.status(409).json({ message: 'Already account with this email' });
        });
    };
    sendVerificationEmail(recipient_email, OTP)
    .then((response) => res.send(response.message))
    .catch((error) => res.status(500).send(error.message));
    });

app.post('/reset-password', (req, res) => {
    const { email, pwd} = req.body;

    if (!email || !pwd) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    const checkSql = "SELECT Password FROM users WHERE Email = ?";
    db.query(checkSql, [email], (err, results) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        if (results.length === 0) return res.status(404).json({ message: 'User not found' });

        const currentHashedPassword = results[0].Password;

        // Compare the new password with the old hashed password
        bcrypt.compare(pwd, currentHashedPassword, (err, isSame) => {
            if (err) return res.status(500).json({ message: 'Server error' });
            
            if (isSame) {
                return res.status(400).json({ message: 'New password cannot be the same as the old password' });
            }

            // Hash the new password
            bcrypt.hash(pwd, 10, (err, hash) => {
                if (err) return res.status(500).json({ message: 'Server error' });

                const updateSql = "UPDATE users SET Password = ? WHERE Email = ?";
                db.query(updateSql, [hash, email], (err, result) => {
                    if (err) return res.status(500).json({ message: 'Server error' });
                    if (result.affectedRows === 0) {
                        return res.status(404).json({ message: 'User not found' });
                    }
                    return res.status(200).json({ message: 'Password reset successful' });
                });
            });
        });
    });
});