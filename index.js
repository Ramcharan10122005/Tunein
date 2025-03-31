import express from "express";
import path from "path";
import pg from "pg";
import { fileURLToPath } from "url";
import multer from "multer";
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
const saltrounds=10;
env.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(session({ secret: "yourSecretKey", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

let users = [
    { email: "202311047@diu.iiitvadodara.ac.in", username: "Ramcharan", password: "hashedPassword" },
    { email: "kundenaramcharan@gmail.com", username: "Ramcharan", password: "hashedPassword" },
    { email: "202311063@diu.iiitvadodara.ac.in", username: "Ramcharan", password: "hashedPassword" }
];

let otpStore = {};
const db=new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database:process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port:process.env.DB_PORT,
})
db.connect()
    .then(() => console.log("✅ Connected to PostgreSQL"))
    .catch(err => console.error("❌ Database connection error:", err));
// Home Route
app.get("/", (req, res) => {
    res.render('dashboard',{
        user:req.session.username,
    });
});
app.get("/home",(req,res)=>{
    res.redirect("/");
})
// Authentication Routes
app.get("/login", (req, res) => {
    res.render("login",{
        error: false, 
        errorType: "user-exists" || "",
        errorMessage: "User with this username or email already exists",
    });
});
app.get("/signup", (req, res) => {
    res.render("signup",{
        error: false, 
        errorType: "user-exists" || "",
        errorMessage: "User with this username or email already exists",
    });
});
app.get("/reset", (req, res) => {
    res.render("reset",{ 
        error: false, 
        errorType: "user-exists" || "",
        errorMessage: "Invalid Password",
    });
});
app.post("/signup",async(req,res)=>{
    try {
        const { username, email, password } = req.body;

        const user = await db.query("SELECT * FROM users WHERE username = $1 OR email = $2", [username, email]);
        if (user.rows.length > 0) {
            return res.render("signup", { 
                error: true, 
                errorType: "user-exists" || "",
                errorMessage: "User with this username or email already exists",
            });
        }

        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, saltrounds);

        // Insert new user into the database
        const result = await db.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
            [username, email, hashedPassword]
        );
        req.session.authenticated = true;
        req.session.username=username;
        //req.session.user = { id: user.rows[0].id, username: user.rows[0].username };
        res.redirect("/"); 
        console.log(result.rows[0] );
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal Server Error" });
    }
})
app.post("/login",async(req,res)=>{
    try{
        const { username, password } = req.body;
        const user = await db.query("SELECT * FROM users WHERE username = $1", [username]);
        if (user.rows.length === 0) {
            return res.render("login", { 
                error: true, 
                errorType: "user-exists" || "",
                errorMessage: "Invalid username",
            });
        }
        const isValidPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!isValidPassword) {
            return res.render("login", { 
                error: true, 
                errorType: "user-exists" || "",
                errorMessage: "Invalid Password",
            });
        }
        req.session.authenticated = true;
        req.session.username=username;
       // req.session.user = { id: user.rows[0].id, username: user.rows[0].username };
        res.redirect("/"); 
    }
    catch(err){
        console.error(err);
        res.status(500).json({ message: "Internal Server Error" });
    }
})
// Password Reset
app.post("/reset", async(req, res) => {
    const email = req.body.email.trim();
    console.log("Entered Email:", email);
    const user = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    console.log(user);
    if (user.rows.length != 0) {
        req.session.resetEmail = email; 
        console.log(req.session);
        res.redirect("/verify-2fa");
    } else {
        return res.render("reset", { 
            error: true, 
            errorType: "user-exists" || "",
            errorMessage: "Invalid Email",
        });
    }
});
app.post("/new",async(req,res)=>{
    try{
        const { password, confirm_password } = req.body;
        const email = req.session.resetEmail;
        if (password !== confirm_password) {
            return res.render("new", { 
                error: true, 
                errorType: "user-exists" || "",
                errorMessage: "Passwords do not match",
            })
        }
        const hashedPassword = await bcrypt.hash(password, saltrounds);
        const user = await db.query("update users SET password = $1 WHERE email = $2", [hashedPassword, email]);
        req.session.resetEmail = null;
        res.redirect("/login");
    }
    catch(err){
        console.error(error);
        res.status(500).render("reset", { 
            error: true, 
            errorType: "server-error",
            errorMessage: "An error occurred. Please try again.",
        });
    }
})
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
        return res.redirect("/new");
    }

    res.send("Invalid OTP, try again.");
});

// Dashboard (Authenticated Route)
app.get("/new",(req,res)=>{
    if(req.session.authenticated)
    res.render("new",{ 
        error: false, 
        errorType: "user-exists" || "",
        errorMessage: "Passwords do not match",
    });
    else{
        res.redirect("/reset");
    }
})
app.get("/dashboard", (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect("/login");
    }
    res.send("Welcome to your dashboard!");
});
app.get("/admin", async (req, res) => {
    const result = await db.query("SELECT * FROM songs ORDER BY id DESC");
    res.render("add", { songs: result.rows });
});
app.post("/add-song", upload.fields([{ name: "song" }, { name: "cover" }]), async (req, res) => {
    try {
        const { title, artist, duration } = req.body;
        const songFile = req.files["song"][0].buffer;
        const coverFile = req.files["cover"][0].buffer;

        await db.query(
            "INSERT INTO songs (title, artist, duration, song, cover) VALUES ($1, $2, $3, $4, $5)",
            [title, artist, duration, songFile, coverFile]
        );

        res.redirect("/admin");
    } catch (error) {
        console.error("Error inserting song:", error);
        res.status(500).send("Error saving the song");
    }
});
// liked songs (Authenticated Route)
app.use((req, res, next) => {
    req.user = { userId: 5, username: "ijk" }; // Hardcoded test user
    next();
});

app.get("/liked-songs", (req, res) => {
    const loggedInUser = req.user; // Get the "logged-in" user (hardcoded)

    if (!loggedInUser) {
        return res.redirect("/login");
    }

    const likedSongs = [
        { userId: 5, username: "ijk", songName: "Industry Baby", artist: "Lil Nas X & Jack Harlow" },
        { userId: 5, username: "ijk", songName: "Good 4 U", artist: "Olivia Rodrigo" },
        { userId: 5, username: "ijk", songName: "Starboy", artist: "The Weeknd" },
        { userId: 5, username: "ijk", songName: "Sunflower", artist: "Post Malone & Swae Lee" },
        { userId: 5, username: "ijk", songName: "Uptown Funk", artist: "Mark Ronson ft. Bruno Mars" },
        { userId: 7, username: "xyz", songName: "Blinding Lights", artist: "The Weeknd" }
    ];

    // Filter liked songs for the "logged-in" user
    const userLikedSongs = likedSongs.filter(song => song.username === loggedInUser.username);

    res.render("liked.ejs", { 
        likedSongs, 
        loggedInUserId: loggedInUser.userId // Pass userId to EJS
    });

});
app.get("/play/:title", async (req, res) => {
    try {
        const title = decodeURIComponent(req.params.title);
        console.log(title);

        const result = await db.query("SELECT title, artist, cover, song FROM songs WHERE title = $1", [title]);

        if (result.rows.length === 0) {
            return res.status(404).send("Song not found");
        }

        const songdet = result.rows[0];

        // Convert image and audio from `bytea` to Base64
        const imageBase64 = `data:image/jpeg;base64,${songdet.cover.toString("base64")}`;
        const audioBase64 = `data:audio/mpeg;base64,${songdet.song.toString("base64")}`;

        // Render EJS with song details
        res.render("dashboard", {
            song: {
                title: songdet.title,
                artist: songdet.artist,
                image: imageBase64,
                audio: audioBase64,
            },
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
