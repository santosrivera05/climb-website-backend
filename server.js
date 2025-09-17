import express from 'express';
import mysql from 'mysql2/promise';
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

console.error("middleware log test");
console.error("middleware error test");

const app = express();
const apiRouter = express.Router();
app.use(cookieParser()); 
app.use(cors({
  origin: 'https://depaulclimbing.com',
  credentials: true
}));

const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// to hopefully see webhook logs in railway
app.use((req, res, next) => {
  console.error("➡️ Incoming request:", req.method, req.url);
  next();
});

app.post("/webhook", express.raw({ type: "*/*" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];

    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("❌ Webhook signature verification failed:", err.message);
      return res.sendStatus(400);
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;

      // TODO: pull from session.metadata
      const email = session.metadata.email
      const passes = session.metadata.passes
      const type = session.metadata.type

      console.error("Webhook received:", { email, passes, type });
      process.stdout.write(""); // flush stdout buffer

      try {
        if (type === "dues") {
          await db.execute("UPDATE users SET Dues = 1 WHERE Email = ?", [email]);
          console.error(`✅ Dues paid for ${email}`);
        } else if (type === "passes") {
          await db.execute(
            "UPDATE users SET Passes = Passes + ? WHERE Email = ?",
            [parseInt(passes), email]
          );
          console.error(`✅ Added ${passes} passes for ${email}`);
        }
      } catch (dbErr) {
        console.error("❌ Database update failed:", dbErr);
        return res.status(500).json({ received: false, error: "DB error" });
      }
    }
    // ✅ Always respond to Stripe that the event was received
    res.json({ received: true });
  }
);

app.get("/webhook", (req, res) => {
  console.error("🔥 GET request to webhook endpoint");
  res.json({ status: "Webhook endpoint is reachable", timestamp: new Date().toISOString() });
});

app.use(express.json());

app.use('/api', apiRouter); // Mount API router

apiRouter.get('/refresh', async (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) return res.status(401).json({ message: 'No refresh token provided' });

  try {
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, 'your_refresh_token_secret');

    // Fetch user from DB
    const [results] = await db.execute("SELECT * FROM users WHERE Email = ?", [decoded.email]);
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
      roles: [dbUser.Role], // Keep array format for frontend
      user: userData,
    });

  } catch (err) {
    console.error('Refresh token error:', err);
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(403).json({ message: 'Invalid or expired refresh token' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user database
apiRouter.get('/users', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM users');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err });
  }
});

// Get check-ins database
apiRouter.get('/check-ins', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM `check-ins` ORDER BY DateTime DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err });
  }
});

// login route
apiRouter.post('/auth', async (req, res) => {
  const { user, pwd } = req.body;
  try {
    const [results] = await db.execute("SELECT * FROM users WHERE Email = ?", [user]);
    if (results.length === 0) return res.status(401).json({ message: 'Email not found' });

    const dbUser = results[0];
    const match = await bcrypt.compare(pwd, dbUser.Password);
    if (!match) return res.status(401).json({ message: 'Incorrect password' });

    const accessToken = jwt.sign(
      { email: dbUser.Email, role: dbUser.Role },
      'your_access_token_secret',
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { email: dbUser.Email, role: dbUser.Role },
      'your_refresh_token_secret',
      { expiresIn: '7d' }
    );

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true, // change to true in production (https)
      sameSite: 'Strict',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const { Password, ...userData } = dbUser;
    return res.json({ user: userData, accessToken });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err });
  }
});

apiRouter.post('/logout', (req, res) => {
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: true, // set to true in production (HTTPS)
        sameSite: 'Strict',
        path: '/'
    });
    return res.json({ message: 'Logged out successfully' });
});

// inserts new user into users database
apiRouter.post('/register', async (req, res) => {
  const { email, pwd, firstName, lastName, membership } = req.body;
  console.error(email, pwd, firstName, lastName, membership);

  try {
    // hash password with async/await instead of callback
    const hash = await bcrypt.hash(pwd, 10);

    const insertSql = `INSERT INTO users (Email, First, Last, Password, Passes, Role, Dues, Membership) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;

    const [result] = await db.execute(insertSql, [
      email, firstName, lastName, hash, 0, 2001, 0, membership
    ]);

    return res.status(201).json({ message: 'User registered', userId: result.insertId });
  } catch (err) {
    return res.status(500).json({ message: 'Server error', error: err });
  }
});

apiRouter.post("/use-pass", async (req, res) => {
  const { firstName, lastName, email, membership} = req.body;
  if (!email) return res.status(400).json({ message: "Email not found" });

  const now = new Date();
  const cstDate = new Date(now.toLocaleString("en-US", { timeZone: "America/Chicago" }));

    // Format as YYYY-MM-DD HH:MM:SS for MySQL
    const currentDateTime = cstDate.getFullYear() + '-' +
        String(cstDate.getMonth() + 1).padStart(2, '0') + '-' +
        String(cstDate.getDate()).padStart(2, '0') + ' ' +
        String(cstDate.getHours()).padStart(2, '0') + ':' +
        String(cstDate.getMinutes()).padStart(2, '0') + ':' +
        String(cstDate.getSeconds()).padStart(2, '0');

    console.error(currentDateTime); // Will output: 2025-08-05 19:48:42

  try {
    if (membership === 0) { // if user does not have membership, skip passes
        // 1. Try to use a pass
        const [updateResult] = await db.execute(
        `UPDATE users SET Passes = Passes - 1 WHERE Email = ? AND Passes > 0`,
        [email]
        );

        if (updateResult.affectedRows === 0) {
        return res.status(404).json({ message: "User not found or no passes left" });
        }
    }

    // 2. Insert into check-ins table
    await db.execute(
      "INSERT INTO `check-ins` (First, Last, Email, Membership, DateTime) VALUES (?, ?, ?, ?, ?)",
      [firstName, lastName, email, membership, currentDateTime]
    );

    return res.status(200).json({
      message: "✅ Pass used and check-in recorded",
      dateTime: new Date(currentDateTime).toISOString(),
    });
  } catch (err) {
    console.error("❌ Database error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

apiRouter.post('/undo-check-in', async (req, res) => {
    const { email, membership, dateTime } = req.body;

    try {
        // Remove from check-ins table
        const [result] = await db.execute(
            "DELETE FROM `check-ins` WHERE Email = ? AND DateTime = ?",
            [email, dateTime]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Check-in not found" });
        }

        // If user is not a member, restore their pass
        if (membership === 0) {
            await db.execute(
                "UPDATE users SET Passes = Passes + 1 WHERE Email = ?",
                [email]
            );
        }

        return res.status(200).json({ 
            message: "✅ Check-in undone",
            email: email,
            dateTime: dateTime
         });
    } catch (err) {
        console.error("❌ Database error:", err);
        return res.status(500).json({ message: "Server error" });
    }
});

apiRouter.post('/purchase-passes', async (req, res) => {
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
            success_url: "https://depaulclimbing.com/success", // /success
            cancel_url: "https://depaulclimbing.com/cancel", // /cancel
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
apiRouter.post('/purchase-dues', async (req, res) => {
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
        success_url: "https://depaulclimbing.com/success", // /success
        cancel_url: "https://depaulclimbing.com/cancel", // /cancel
        metadata: { email, type: "dues" },
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

        console.error(data); // logs response data
        return data;
    } catch (error) {
        console.error(error); //logs any error
    }
};

apiRouter.post("/send-recovery-email", async (req, res) => {
  const { recipient_email, pwd, firstName, OTP } = req.body;
  console.error(recipient_email, pwd, firstName, OTP);

  try {
    if (!firstName) {
      // Recovery flow: check if user exists
      const [results] = await db.execute("SELECT * FROM users WHERE Email = ?", [
        recipient_email,
      ]);

      if (results.length === 0) {
        return res.status(404).json({ message: "No account with this email" });
      }
    } else {
      // Registration flow: check if account already exists
      if (!recipient_email || !pwd) {
        return res
          .status(400)
          .json({ message: "Email and password required" });
      }

      const [results] = await db.execute("SELECT * FROM users WHERE Email = ?", [
        recipient_email,
      ]);

      if (results.length > 0) {
        return res
          .status(409)
          .json({ message: "Already account with this email" });
      }
    }
    // ✅ If checks pass, send email
    const response = await sendVerificationEmail(recipient_email, OTP);
    return res.send(response.message);
  } catch (err) {
    console.error("❌ Error in /send-recovery-email:", err);
    return res.status(500).send(err.message || "Server error");
  }
});

apiRouter.post("/reset-password", async (req, res) => {
  const { email, pwd } = req.body;

  if (!email)
    return res.status(400).json({ message: "Email not found" });
  try {
    // 1. Check if user exists
    const [results] = await db.execute(
      "SELECT Password FROM users WHERE Email = ?",
      [email]
    );

    if (results.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const currentHashedPassword = results[0].Password;

    // 2. Compare new password with old
    const isSame = await bcrypt.compare(pwd, currentHashedPassword);
    if (isSame) {
      return res.status(400).json({
        message: "New password cannot be the same as the old password",
      });
    }

    // 3. Hash new password
    const newHashedPassword = await bcrypt.hash(pwd, 10);

    // 4. Update database
    const [updateResult] = await db.execute(
      "UPDATE users SET Password = ? WHERE Email = ?",
      [newHashedPassword, email]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({ message: "Password reset successful" });
  } catch (err) {
    console.error("❌ Error in /reset-password:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Start server
app.listen(3000, () => {
    console.error('Server listening on port 3000');
});