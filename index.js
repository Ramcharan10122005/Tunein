import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import crypto from "crypto";
import nodemailer from "nodemailer";

const app = express();
const port = 3000;

env.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(session({ secret: "yourSecretKey", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

let users = [
    { email: "kundenaramcharan@gmail.com", username: "Ramcharan", password: "hashedPassword" }
];

let otpStore = {};

// Home Route
app.get("/", (req, res) => {
    res.send("hello");
});

// Authentication Routes
app.get("/login", (req, res) => {
    res.render("login");
});
app.get("/signup", (req, res) => {
    res.render("signup");
});
app.get("/reset", (req, res) => {
    res.render("reset");
});

// Password Reset
app.post("/reset", (req, res) => {
    const email = req.body.email;
    const user = users.find(user => user.email === email);
    if (user) {
        req.session.resetEmail = email; // Store email in session
        res.redirect("/verify-2fa");
    } else {
        res.send("Invalid email.");
    }
});

// OTP Verification Page
app.get("/verify-2fa", (req, res) => {
    if (!req.session.resetEmail) {
        return res.redirect("/reset");
    }

    const otp = crypto.randomInt(100000, 999999);
    otpStore[req.session.resetEmail] = otp;

    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: req.session.resetEmail,
        subject: "Your 2FA Verification Code",
        text: `Your 2FA verification code is: ${otp}`
    };

    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            console.error(err);
            return res.send("Error sending email");
        }
        res.render("verify-2fa", { email: req.session.resetEmail });
    });
});

// Verify OTP Route
app.post("/verify-2fa", (req, res) => {
    const email = req.session.resetEmail;
    const userOtp = req.body.otp;

    if (!email || !otpStore[email]) {
        return res.send("Session expired. Please request OTP again.");
    }

    if (otpStore[email] == userOtp) {
        delete otpStore[email]; // Clear OTP
        req.session.authenticated = true;
        return res.redirect("/dashboard");
    }

    res.send("Invalid OTP, try again.");
});

// Dashboard (Authenticated Route)
app.get("/dashboard", (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect("/login");
    }
    res.send("Welcome to your dashboard!");
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
