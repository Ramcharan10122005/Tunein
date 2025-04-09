import express from "express";
import path from "path";
import pg from "pg";
import { fileURLToPath } from "url";
import multer from "multer";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import GitHubStrategy  from "passport-github2";
import session from "express-session";
import env from "dotenv";
import crypto from "crypto";
import nodemailer from "nodemailer";
import Razorpay from "razorpay";
import NodeCache from 'node-cache';
import compression from 'compression';

const app = express();
const port = process.env.PORT || 3000;
const saltrounds = 10;
env.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Initialize cache with a 5-minute TTL
const cache = new NodeCache({ stdTTL: 300, checkperiod: 600 });

// Set up view engine and static files
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, "public")));

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: {
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        }
    })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(passport.initialize());
app.use(passport.session());

// Add compression middleware
app.use(compression());

// Declare isPremium variable
let isPremium = false;

// Add middleware to check premium status
app.use(async (req, res, next) => {
    if (req.session && req.session.userId) {
        try {
            const subscriptionResult = await query(
                `SELECT * FROM premium_users 
                WHERE user_id = $1 
                AND subscription_end_date > CURRENT_TIMESTAMP 
                ORDER BY subscription_end_date DESC 
                LIMIT 1`,
                [req.session.userId]
            );
            
            isPremium = subscriptionResult.rows.length > 0;
        } catch (err) {
            console.error('Error checking premium status:', err);
        }
    } else {
        isPremium = false;
    }
    next();
});

// let users = [
//     { email: "202311047@diu.iiitvadodara.ac.in", username: "Ramcharan", password: "hashedPassword" },
//     { email: "kundenaramcharan@gmail.com", username: "Ramcharan", password: "hashedPassword" },
//     { email: "202311063@diu.iiitvadodara.ac.in", username: "Ramcharan", password: "hashedPassword" }
// ];
let played_times = 0;
let ads = [
    {
        title: "Ad 1",
        image: "/images/ad.png",
        audio: "/ads/ad 1.mp3"
    },
    {
        title: "Ad 2",
        image: "/images/ad.png",
        audio: "/ads/ad 2.mp3"
    },
    {
        title: "Ad 3",
        image: "/images/ad.png",
        audio: "/ads/ad 3.mp3"
    },
    {
        title: "Ad 4",
        image: "/images/ad.png",
        audio: "/ads/ad 4.mp3"
    },
    {
        title: "Ad 5",
        image: "/images/ad.png",
        audio: "/ads/ad 5.mp3"
    },
    {
        title: "Ad 6",
        image: "/images/ad.png",
        audio: "/ads/ad 6.mp3"
    }
];
let otpStore = {};
const db = new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    connectionTimeoutMillis: 5000,
    idle_in_transaction_session_timeout: 10000,
    statement_timeout: 10000
});

// Optimize database pool configuration
const pool = new pg.Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    application_name: 'tunein_app'
});

// Enhanced query function with caching
const query = async (text, params, cacheKey = null) => {
    const start = Date.now();
    
    // Check cache first if cacheKey is provided
    if (cacheKey) {
        const cachedResult = cache.get(cacheKey);
        if (cachedResult) {
            console.log('Cache hit for:', cacheKey);
            return cachedResult;
        }
    }

    try {
        const res = await pool.query(text, params);
        const duration = Date.now() - start;
        console.log('Executed query', { text, duration, rows: res.rowCount });

        // Cache the result if cacheKey is provided
        if (cacheKey && res.rows.length > 0) {
            cache.set(cacheKey, res);
        }

        return res;
    } catch (error) {
        console.error('Error executing query', { text, error });
        throw error;
    }
};

db.connect()
    .then(() => console.log("✅ Connected to PostgreSQL"))
    .catch(err => console.error("❌ Database connection error:", err));
// Home Route
app.get("/", (req, res) => {
    res.render('dashboard', {
        user: req.session.username,
    });
});
app.get("/home", (req, res) => {
    res.redirect("/");
})
// Authentication Routes
app.get("/auth/github", 
    passport.authenticate("github", { 
        scope: ["user:email"] 
    }
));
app.get(
    "/auth/github/callback",
    passport.authenticate("github", { failureRedirect: "/login" }),
    async (req, res) => {
        if (req.user) {
            req.session.username = req.user.username;
            req.session.userId = req.user.id;
            
            // Check premium status
            const subscriptionResult = await query(
                `SELECT * FROM premium_users 
                WHERE user_id = $1 
                AND subscription_end_date > CURRENT_TIMESTAMP 
                ORDER BY subscription_end_date DESC 
                LIMIT 1`,
                [req.user.id]
            );
            
            isPremium = subscriptionResult.rows.length > 0;
            console.log("Session after Github auth:", req.session);
        }
        res.redirect('/');
    }
);
app.get("/auth/google",
    passport.authenticate("google", {
        scope: ["profile", "email"],
    })
)
app.get(
    "/auth/google/callback",
    passport.authenticate("google", {
        failureRedirect: "/login",
    }),
    async (req, res) => {
        if (req.user) {
            req.session.username = req.user.username;
            req.session.userId = req.user.id;
            
            // Check premium status
            const subscriptionResult = await query(
                `SELECT * FROM premium_users 
                WHERE user_id = $1 
                AND subscription_end_date > CURRENT_TIMESTAMP 
                ORDER BY subscription_end_date DESC 
                LIMIT 1`,
                [req.user.id]
            );
            
            isPremium = subscriptionResult.rows.length > 0;
            console.log("Session after Google auth:", req.session);
        }
        res.redirect('/');
    }
);
app.get("/login", (req, res) => {
    res.render("login", {
        error: false,
        errorType: "user-exists" || "",
        errorMessage: "User with this username or email already exists",
    });
});
app.get("/signup", (req, res) => {
    res.render("signup", {
        error: false,
        errorType: "user-exists" || "",
        errorMessage: "User with this username or email already exists",
    });
});
app.get("/random-song", async (req, res) => {
    try {
        const result = await query("SELECT title FROM songs ORDER BY RANDOM() LIMIT 1");
        if (result.rows.length > 0) {
            const randomSong = result.rows[0];
            res.redirect(`/play/${encodeURIComponent(randomSong.title)}`);
        } else {
            res.redirect("/");
        }
    } catch (err) {
        console.error("Error getting random song:", err);
        res.redirect("/");
    }
})
app.get("/reset", (req, res) => {
    res.render("reset", {
        error: false,
        errorType: "user-exists" || "",
        errorMessage: "Invalid Password",
    });
});
app.get("/Mood-based",(req,res)=>{
    if (!req.session.userId) {
        return res.redirect("/login");
    }
    res.render("moods.ejs", {
        user: req.session.username
    });
})
app.get("/based", async (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }
    try {
        let mood = req.query.mood;
        if (!mood) {
            return res.status(400).render('error', {
                error: 'Mood parameter is required'
            });
        }
        
        mood = mood.toLowerCase();
        const songs = await query("SELECT * FROM songs WHERE mood = $1", [mood]);

        res.render("based.ejs", {
            songs: songs.rows,
            mood: mood,
            user: req.session.username
        });
    } catch (err) {
        console.error("Error fetching mood-based songs:", err);
        res.status(500).render("error", {
            error: "Error loading mood-based songs"
        });
    }
});
app.post("/signup", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        const user = await query("SELECT * FROM users WHERE username = $1 OR email = $2", [username, email]);
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
        const result = await query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
            [username, email, hashedPassword]
        );
        req.session.authenticated = true;
        req.session.username = username;
        //req.session.user = { id: user.rows[0].id, username: user.rows[0].username };
        res.redirect("/");
        console.log(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal Server Error" });
    }
})
app.post("/login", (req, res, next) => {
    passport.authenticate("local", async (err, user, info) => {
      if (err) return next(err);
      if (!user) {
        return res.render("login", {
          error: true,
          errorType: "user-exists" || "",
          errorMessage: info.message,
        });
      }
      
      req.logIn(user, async (err) => {
        if (err) return next(err);
        req.session.username = user.username;
        req.session.userId = user.id;

        // Check premium status
        const subscriptionResult = await query(
            `SELECT * FROM premium_users 
            WHERE user_id = $1 
            AND subscription_end_date > CURRENT_TIMESTAMP 
            ORDER BY subscription_end_date DESC 
            LIMIT 1`,
            [user.id]
        );
        
        isPremium = subscriptionResult.rows.length > 0;
        return res.redirect("/"); 
      });
    })(req, res, next);
});
// Add this route before the /reset POST route
app.get("/check-email", async (req, res) => {
    try {
        const email = req.query.email;
        const result = await query("SELECT * FROM users WHERE email = $1", [email]);
        res.json({ exists: result.rows.length > 0 });
    } catch (err) {
        console.error("Error checking email:", err);
        res.status(500).json({ error: "Server error" });
    }
});
// Password Reset
app.post("/reset", async (req, res) => {
    const email = req.body.email.trim();
    console.log("Entered Email:", email);
    const user = await query("SELECT * FROM users WHERE email = $1", [email]);
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
app.post("/new", async (req, res) => {
    try {
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
        const user = await query("update users SET password = $1 WHERE email = $2", [hashedPassword, email]);
        req.session.resetEmail = null;
        res.redirect("/login");
    }
    catch (err) {
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
app.get("/new", (req, res) => {
    if (req.session.authenticated)
        res.render("new", {
            error: false,
            errorType: "user-exists" || "",
            errorMessage: "Passwords do not match",
        });
    else {
        res.redirect("/reset");
    }
})
app.get("/dashboard", (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect("/login");
    }
    res.send("Welcome to your dashboard!");
});

app.get("/like/:title", async (req, res) => {
    try {
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ error: "User not authenticated" });
        }

        const title = decodeURIComponent(req.params.title);
        const lowercaseTitle = title.toLowerCase();
        console.log(title);
        // ✅ Fixed the WHERE clause
        const result = await query("SELECT id FROM songs WHERE title = $1", [lowercaseTitle]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Song not found" });
        }

        const songid = result.rows[0].id;
        const userid = req.session.userId;

        // ✅ Prevents duplicate likes
        await query(
            "INSERT INTO liked (songid, userid) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            [songid, userid]
        );

        res.json({ success: true, message: "Song liked successfully" });
    } catch (error) {
        console.error("Error liking song:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Admin middleware to check if user is authenticated as admin
const isAdmin = async (req, res, next) => {
    if (!req.session.adminAuthenticated) {
        return res.redirect('/admin/login');
    }
    next();
};

// Admin login page route
app.get("/admin/login", (req, res) => {
    res.render("admin-login", {
        error: false,
        errorMessage: ""
    });
});

// Admin login route
app.post("/admin/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Check if admin exists
        const result = await query("SELECT * FROM admin WHERE username = $1", [username]);
        
        if (result.rows.length === 0) {
            return res.render("admin-login", {
                error: true,
                errorMessage: "Invalid username or password"
            });
        }

        const admin = result.rows[0];
        const validPassword = await bcrypt.compare(password, admin.password);

        if (!validPassword) {
            return res.render("admin-login", {
                error: true,
                errorMessage: "Invalid username or password"
            });
        }

        // Set admin session
        req.session.adminAuthenticated = true;
        req.session.adminUsername = username;
        
        res.redirect("/admin");
    } catch (err) {
        console.error("Admin login error:", err);
        res.render("admin-login", {
            error: true,
            errorMessage: "An error occurred during login"
        });
    }
});

// Admin logout route
app.get("/admin/logout", (req, res) => {
    req.session.adminAuthenticated = false;
    req.session.adminUsername = null;
    res.redirect("/admin/login");
});

// Modify the existing admin route to use the isAdmin middleware
app.get("/admin", isAdmin, async (req, res) => {
    try {
        const songsResult = await query("SELECT * FROM songs ORDER BY id DESC");
        const unreadFeedbackResult = await query("SELECT COUNT(*) FROM feedback WHERE is_read = false");
        const feedbacksResult = await query("SELECT * FROM feedback ORDER BY created_at DESC");
        
        res.render("add", { 
            songs: songsResult.rows,
            adminUsername: req.session.adminUsername,
            unreadFeedbackCount: parseInt(unreadFeedbackResult.rows[0].count),
            feedbacks: feedbacksResult.rows
        });
    } catch (error) {
        console.error("Error loading admin page:", error);
        res.status(500).send("Error loading admin page");
    }
});

app.post("/add-song", upload.fields([{ name: "song" }, { name: "cover" }]), async (req, res) => {
    try {
        const { title, artist, duration, language, genre, mood } = req.body;
        const songFile = req.files["song"][0].buffer;
        const coverFile = req.files["cover"][0].buffer;

        // Convert all text fields to lowercase
        const lowercaseTitle = title.toLowerCase();
        const lowercaseArtist = artist.toLowerCase();
        const lowercaseLanguage = language.toLowerCase();
        const lowercaseGenre = genre.toLowerCase();
        const lowercaseMood = mood.toLowerCase();

        await query(
            "INSERT INTO songs (title, artist, duration, song, cover, language, genre, mood) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            [lowercaseTitle, lowercaseArtist, duration, songFile, coverFile, lowercaseLanguage, lowercaseGenre, lowercaseMood]
        );

        res.redirect("/admin");
    } catch (error) {
        console.error("Error inserting song:", error);
        res.status(500).send("Error saving the song");
    }
});

// Route to delete a song
app.post("/delete-song", isAdmin, async (req, res) => {
    try {
        const { songId } = req.body;
        
        // First delete from liked songs and playlists
        await query("DELETE FROM liked WHERE songid = $1", [songId]);
        await query("DELETE FROM playlists WHERE song_id = $1", [songId]);
        
        // Then delete the song itself
        await query("DELETE FROM songs WHERE id = $1", [songId]);
        
        res.redirect("/admin");
    } catch (error) {
        console.error("Error deleting song:", error);
        res.status(500).send("Error deleting the song");
    }
});

// Route for playlist 
app.get("/playlists", async(req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    try {
        const userId = req.session.userId;
        // Modified query to get distinct playlists
        const playlistsResult = await query(`
            SELECT DISTINCT ON (playlist_name) 
                id,
                playlist_name,
                user_id
            FROM playlists 
            WHERE user_id = $1 
            ORDER BY playlist_name, id
        `, [userId]);
        
        // Format playlists data for the template
        const playlists = playlistsResult.rows.map(playlist => {
            return {
                userId: playlist.user_id,
                username: req.session.username,
                name: playlist.playlist_name,
                songs: [] // You might want to fetch songs for each playlist here
            };
        });
        
        res.render("playlist.ejs", { 
            user: req.session.username, 
            playlists: playlists, 
            loggedInUserId: userId 
        });
    } catch (error) {
        console.error("Error fetching playlists:", error);
        res.status(500).send("Error fetching playlists");
    }
});

app.post("/create-playlist", async(req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: "User not authenticated" });
    }
    const name=req.body.playlistName;
    await query("INSERT INTO playlists (playlist_name, user_id) VALUES ($1, $2)", [name, req.session.userId]);
    res.redirect("/playlists");
})
// Route to display songs in a playlist
app.get("/playlists/songs", async (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    const playlistName = req.query.name;
    const loggedInUserId = req.session.userId;
    req.session.playlistName=playlistName;
    try {
        // Fetch all playlists and their songs for the logged-in user
        const playlistsResult = await query(`
            SELECT 
                p.id AS playlist_id,
                p.playlist_name AS playlist_name,
                p.user_id,
                u.username,
                s.id AS song_id,
                s.title AS song_title,
                s.artist,
                s.cover,
                s.song
            FROM playlists p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN playlists ps ON ps.id = p.id
            LEFT JOIN songs s ON s.id = ps.song_id
            WHERE p.user_id = $1
            ORDER BY p.playlist_name
        `, [loggedInUserId]);

        // Organize data
        const playlistsMap = new Map();

        playlistsResult.rows.forEach(row => {
            const key = row.playlist_name;

            if (!playlistsMap.has(key)) {
                playlistsMap.set(key, {
                    id: row.playlist_id,
                    userId: row.user_id,
                    username: row.username,
                    name: row.playlist_name,
                    songs: []
                });
            }

            if (row.song_title && row.artist) {
                playlistsMap.get(key).songs.push({
                    id: row.song_id,
                    name: row.song_title,
                    artist: row.artist,
                    image: row.cover ? `data:image/jpeg;base64,${row.cover.toString('base64')}` : null,
                    audio: row.song ? `data:audio/mpeg;base64,${row.song.toString('base64')}` : null
                });
            }
        });

        const playlists = Array.from(playlistsMap.values());

        // Find selected playlist
        const selectedPlaylist = playlists.find(p => p.name === playlistName);

        if (!selectedPlaylist) {
            return res.status(404).send("Playlist not found");
        }

        res.render("playlist_songs", {
            playlist: selectedPlaylist,
            playlists: playlists,
            loggedInUserId: loggedInUserId
        });

    } catch (error) {
        console.error("Error retrieving playlists:", error);
        res.status(500).send("Internal Server Error");
    }
});

// liked songs (Authenticated Route)
app.get("/rand", async (req, res) => {
    try {
        const result = await query(
            "SELECT s.title, s.artist, s.cover, s.song FROM liked l JOIN songs s ON l.songid = s.id WHERE l.userid = $1 ORDER BY RANDOM() LIMIT 1", 
            [req.session.userId]
        );
        console.log(result.rows);
        if (result.rows.length === 0) {
            return res.status(404).send("Song not found");
        }

        const songdet = result.rows[0];

        // Convert image and audio from `bytea` to Base64
        const imageBase64 = `data:image/jpeg;base64,${songdet.cover.toString("base64")}`;
        const audioBase64 = `data:audio/mpeg;base64,${songdet.song.toString("base64")}`;

        // Increment played_times before checking for ad
        played_times++;
        console.log(played_times);
        // Check if it's time to show an ad (every 5 clicks) and user is not premium
        const shouldShowAd = !isPremium && played_times % 5 === 0;
        const currentAd = shouldShowAd ? getNextAd() : null;

        // Send response with song details and ad info
        res.json({
            title: songdet.title,
            artist: songdet.artist,
            image: imageBase64,
            audio: audioBase64,
            showAd: shouldShowAd,
            ad: currentAd
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});
app.get("/song/:title", async (req, res) => {
    try {
        const title = decodeURIComponent(req.params.title);
        const lowercaseTitle = title.toLowerCase();
        console.log(title);

        const result = await query("SELECT title, artist, cover, song FROM songs WHERE title = $1", [lowercaseTitle]);

        if (result.rows.length === 0) {
            return res.status(404).send("Song not found");
        }

        const songdet = result.rows[0];

        // Convert image and audio from `bytea` to Base64
        const imageBase64 = `data:image/jpeg;base64,${songdet.cover.toString("base64")}`;
        const audioBase64 = `data:audio/mpeg;base64,${songdet.song.toString("base64")}`;

        // Increment played_times before checking for ad
        played_times++;
        console.log(played_times);
        // Check if it's time to show an ad (every 5 clicks) and user is not premium
        const shouldShowAd = !isPremium && played_times % 5 === 0;
        const currentAd = shouldShowAd ? getNextAd() : null;

        // Send response with song details and ad info
        res.json({
            title: songdet.title,
            artist: songdet.artist,
            image: imageBase64,
            audio: audioBase64,
            showAd: shouldShowAd,
            ad: currentAd
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});
app.post("/remove-liked", async (req, res) => {
    const songId = req.body.songId;
    await query("DELETE FROM liked WHERE songid = $1", [songId]);
    res.redirect("/liked-songs");
})
app.post("/remove-playlist", async (req, res) => {
    const songName = req.body.songName ;
    const userId = req.body.userId;
    await query("DELETE FROM playlists WHERE playlist_name = $1 AND user_id = $2", [songName, userId]);
    res.redirect("/playlists");
})
app.post("/remove-from-playlist", async (req, res) => {
    const playlistId = req.body.playlistId;
    const songId = req.body.songId;
    
    // First, get the playlist to verify ownership
    const playlistCheck = await query(
        "SELECT * FROM playlists WHERE id = $1 AND user_id = $2",
        [playlistId, req.session.userId]
    );
    
    if (playlistCheck.rows.length === 0) {
        return res.status(403).send("You don't have permission to modify this playlist");
    }
    console.log(playlistId, songId, req.session.userId);
    // Update the playlist to remove the song
    await query(
        "UPDATE playlists SET song_id = NULL WHERE song_id = $1 AND user_id = $2",
        [songId, req.session.userId]
    );
    
    res.redirect("/playlists/songs?name=" + encodeURIComponent(req.session.playlistName));
})
app.get("/liked-songs", async (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    try {
        // Get all liked songs for the current user with song details
        const result = await query(`
            SELECT 
                s.id, 
                s.title, 
                s.artist, 
                EXTRACT(HOUR FROM s.duration) AS hours,
                EXTRACT(MINUTE FROM s.duration) AS minutes,
                EXTRACT(SECOND FROM s.duration) AS seconds,
                s.genre, 
                s.mood,
                s.cover, 
                u.username, 
                l.created_at
            FROM liked l
            JOIN songs s ON l.songid = s.id
            JOIN users u ON l.userid = u.id
            WHERE l.userid = $1
            ORDER BY l.created_at DESC
        `, [req.session.userId]);


        // Convert cover images to base64 and format duration
        const likedSongs = result.rows.map(song => ({
            ...song,
            cover: song.cover ? `data:image/jpeg;base64,${song.cover.toString('base64')}` : null,
            duration: formatDuration({
                hours: song.hours,
                minutes: song.minutes,
                seconds: song.seconds
            })
        }));
        console.log(likedSongs.length);
        res.render("liked", {
            likedSongs: likedSongs,
            loggedInUserId: req.session.userId,
            user: req.session.username
        });
    } catch (err) {
        console.error("Error fetching liked songs:", err);
        res.status(500).send("Error fetching liked songs");
    }
});

// Helper function to format duration
function formatDuration(duration) {
    if (!duration) return "0:00";
    
    // If duration is an object with hours, minutes, seconds
    if (typeof duration === 'object' && duration.hours !== undefined) {
        const hours = Math.floor(duration.hours) || 0;
        const minutes = Math.floor(duration.minutes) || 0;
        const seconds = Math.floor(duration.seconds) || 0;
        
        if (hours > 0) {
            return `${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        } else {
            return `${minutes}:${seconds.toString().padStart(2, '0')}`;
        }
    }
    
    // Handle string format like "00:03:59"
    const parts = duration.toString().split(':');
    if (parts.length === 3) {
        const [hours, minutes, seconds] = parts;
        if (hours === "00") {
            return `${parseInt(minutes)}:${seconds}`;
        }
        return `${parseInt(hours)}:${minutes}:${seconds}`;
    }
    
    // Handle string format like "3:59"
    if (parts.length === 2) {
        const [minutes, seconds] = parts;
        return `${parseInt(minutes)}:${seconds}`;
    }
    
    return "0:00";
}

// Function to get next ad
function getNextAd() {
    const adIndex = Math.floor((played_times - 1) / 5) % ads.length;
    return ads[adIndex];
}

app.get("/play/:title", async (req, res) => {
    try {
        const title = decodeURIComponent(req.params.title);
        const lowercaseTitle = title.toLowerCase();
        console.log(title);

        const result = await query("SELECT title, artist, cover, song FROM songs WHERE title = $1", [lowercaseTitle]);

        if (result.rows.length === 0) {
            return res.status(404).send("Song not found");
        }

        const songdet = result.rows[0];

        // Convert image and audio from `bytea` to Base64
        const imageBase64 = `data:image/jpeg;base64,${songdet.cover.toString("base64")}`;
        const audioBase64 = `data:audio/mpeg;base64,${songdet.song.toString("base64")}`;

        // Increment played_times before checking for ad
        played_times++;

        // Check if it's time to show an ad (every 5 clicks) and user is not premium
        const shouldShowAd = !isPremium && played_times % 5 === 0;
        const currentAd = shouldShowAd ? getNextAd() : null;

        // Render EJS with song details and ad info
        res.render("dashboard", {
            song: {
                title: songdet.title,
                artist: songdet.artist,
                image: imageBase64,
                audio: audioBase64,
            },
            user: req.session.username,
            showAd: shouldShowAd,
            ad: currentAd,
            played_times: played_times // Pass the counter to the view
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});

// Add endpoint to get the next ad
app.get("/api/next-ad", (req, res) => {
    const ad = getNextAd();
    res.json(ad);
});

// Add endpoint to handle song plays and return ad information
app.post("/api/song-played", (req, res) => {
    // Increment the played_times counter
    played_times++;
    
    // Check if it's time to show an ad (after 5 songs) and user is not premium
    const shouldShowAd = !isPremium && played_times % 5 === 0;
    const currentAd = shouldShowAd ? getNextAd() : null;
    
    // Return response with ad information
    res.json({
        showAd: shouldShowAd,
        ad: currentAd,
        playedTimes: played_times
    });
});

passport.use(
    "local",
    new Strategy(async function verify(username, password, cb) {
      try {
        const result = await query("SELECT * FROM users WHERE username = $1", [
          username,
        ]);
  
        if (result.rows.length === 0) {
          return cb(null, false, { message: "Invalid username" });
        }
  
        const user = result.rows[0];
        const storedHashedPassword = user.password;
  
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          }
  
          if (valid) {
            return cb(null, user); // Successful login
          } else {
            return cb(null, false, { message: "Invalid password" });
          }
        });
      } catch (err) {
        console.log(err);
        return cb(err);
      }
    })
  );
  
  passport.use(
    "google",
    new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://tunein-9fww7k5ln-ramcharan10122005s-projects.vercel.app/auth/google/callback",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
      passReqToCallback: true
    },
    async (req, accessToken, refreshToken, profile, cb) => {
      try {
        console.log("Google profile received:", profile);
        const email = profile.emails?.[0]?.value;
        const username = profile.displayName || profile.emails?.[0]?.value.split('@')[0];
        
        if (!email) {
          return cb(new Error("No email found in Google profile"));
        }

        const result = await query("SELECT * FROM users WHERE email = $1", [email]);
        
        if(result.rows.length === 0) {
          // Create new user
          const newUser = await query(
            "INSERT INTO users(username, email, password) VALUES($1, $2, $3) RETURNING *",
            [username, email, "google_oauth"]
          );
          return cb(null, {
            id: newUser.rows[0].id,
            username: username,
            email: email
          });
        } else {
          // Return existing user
          return cb(null, {
            id: result.rows[0].id,
            username: result.rows[0].username,
            email: result.rows[0].email
          });
        }
      } catch(err) {
        console.log("Error in Google Strategy:", err);
        return cb(err);
      }
    })
);
passport.use(
    "github",
    new GitHubStrategy(
        {
            clientID: process.env.GITHUB_CLIENT_ID,
            clientSecret: process.env.GITHUB_CLIENT_SECRET,
            callbackURL: "https://tunein-3fgm2i353-ramcharan10122005s-projects.vercel.app/auth/github/callback",
        },
        async (accessToken, refreshToken, profile, cb) => {
            try {
                console.log("GitHub profile received:", profile);

                const email = profile.emails?.[0]?.value || "";
                const username = profile.username || profile.displayName || "GitHubUser";

                // Check if user already exists in the database by email
                const result = await query("SELECT * FROM users WHERE email = $1", [email]);

                if (result.rows.length === 0) {
                    // Insert new user into the database
                    const newUser = await query(
                        "INSERT INTO users(username, email, password) VALUES($1, $2, $3) RETURNING *",
                        [username, email, "github"]
                    );

                    return cb(null, {
                        id: newUser.rows[0].id,
                        username: newUser.rows[0].username,
                        email: newUser.rows[0].email,
                    });
                } else {
                    // User exists, return existing user
                    return cb(null, {
                        id: result.rows[0].id,
                        username: result.rows[0].username,
                        email: result.rows[0].email,
                    });
                }
            } catch (err) {
                console.error("Error in GitHub Strategy:", err);
                return cb(err);
            }
        }
    )
);
passport.serializeUser((user, cb) => {
    cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
    try {
        const result = await query("SELECT * FROM users WHERE id = $1", [id]);
        if (result.rows.length > 0) {
            cb(null, result.rows[0]);
        } else {
            cb(null, false);
        }
    } catch (err) {
        cb(err);
    }
});


// Search endpoint
app.get("/search", async (req, res) => {
    try {
        const query = req.query.q;
        if (!query) {
            return res.json([]);
        }

        const cacheKey = `search_${query}`;
        const result = await query(
            `SELECT title, artist, cover, language, genre, mood 
             FROM songs 
             WHERE LOWER(title) LIKE LOWER($1) 
             OR LOWER(artist) LIKE LOWER($1) 
             OR LOWER(language) LIKE LOWER($1) 
             OR LOWER(genre) LIKE LOWER($1) 
             OR LOWER(mood) LIKE LOWER($1)
             LIMIT 50`,
            [`%${query}%`],
            cacheKey
        );

        res.json(result.rows);
    } catch (err) {
        console.error('Search error:', err);
        res.status(500).json({ error: 'Search failed' });
    }
});
app.post('/create-order', async (req, res) => {
    try {
        console.log('Request body:', req.body);
        console.log('Headers:', req.headers);
        
        const { amount, currency } = req.body;
        
        // Validate required parameters
        if (!amount || !currency) {
            console.error('Missing parameters:', { 
                receivedAmount: amount, 
                receivedCurrency: currency,
                bodyType: typeof req.body,
                contentType: req.headers['content-type']
            });
            return res.status(400).json({ error: 'Amount and currency are required' });
        }

        // Initialize Razorpay with your credentials
        const razorpay = new Razorpay({
            key_id: process.env.RAZORPAY_KEY_ID,
            key_secret: process.env.RAZORPAY_KEY_SECRET
        });
        
        // Convert amount to smallest currency unit (paise)
        const amountInPaise = Math.round(amount * 100);
        
        const options = {
            amount: amountInPaise,
            currency: currency,
            receipt: `receipt_${Date.now()}`,
        };
        
        console.log('Creating Razorpay order with options:', options);
        const order = await razorpay.orders.create(options);
        console.log('Razorpay order created:', order);
        
        res.json({ 
            orderId: order.id,
            amount: amountInPaise,
            currency: currency
        });
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ 
            error: 'Failed to create payment order',
            details: error.message 
        });
    }
});

app.post('/verify-payment', async (req, res) => {
    try {
        console.log('Received payment verification request:', req.body);
        const { razorpay_payment_id, razorpay_order_id, razorpay_signature, plan } = req.body;
        
        if (!req.session.userId) {
            console.error('User not authenticated');
            return res.status(401).json({ success: false, error: 'User not authenticated' });
        }

        // Check if user already has an active subscription
        const activeSubscriptionResult = await query(
            `SELECT * FROM premium_users 
            WHERE user_id = $1 
            AND subscription_end_date > CURRENT_TIMESTAMP 
            ORDER BY subscription_end_date DESC 
            LIMIT 1`,
            [req.session.userId]
        );

        if (activeSubscriptionResult.rows.length > 0) {
            console.log('User already has an active subscription:', activeSubscriptionResult.rows[0]);
            return res.status(400).json({ 
                success: false, 
                error: 'You already have an active premium subscription' 
            });
        }

        if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature || !plan) {
            console.error('Missing required payment parameters:', { 
                payment_id: !!razorpay_payment_id, 
                order_id: !!razorpay_order_id, 
                signature: !!razorpay_signature,
                plan: !!plan 
            });
            return res.status(400).json({ success: false, error: 'Missing payment parameters' });
        }

        // Initialize Razorpay
        const razorpay = new Razorpay({
            key_id: process.env.RAZORPAY_KEY_ID,
            key_secret: process.env.RAZORPAY_KEY_SECRET
        });
        
        // Create the signature verification data
        const body = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(body.toString())
            .digest('hex');

        console.log('Verifying payment signature:', {
            userId: req.session.userId,
            plan: plan,
            payment_id: razorpay_payment_id,
            order_id: razorpay_order_id,
            expected_signature: expectedSignature,
            received_signature: razorpay_signature
        });

        // Verify the signature
        const isValidSignature = expectedSignature === razorpay_signature;
        console.log('Signature verification result:', isValidSignature);

        if (isValidSignature) {
            // Verify payment status with Razorpay
            const payment = await razorpay.payments.fetch(razorpay_payment_id);
            console.log('Payment details from Razorpay:', payment);

            if (payment.status !== 'captured') {
                console.error('Payment not captured:', payment);
                return res.status(400).json({ 
                    success: false, 
                    error: 'Payment not captured',
                    status: payment.status 
                });
            }

            // Update user's premium status in the database
            const userId = req.session.userId;
            const subscriptionEndDate = new Date();
            const amount = plan === 'monthly' ? 120.00 : 1300.00;
            
            // Set subscription end date based on plan
            if (plan === 'monthly') {
                subscriptionEndDate.setMonth(subscriptionEndDate.getMonth() + 1);
            } else if (plan === 'yearly') {
                subscriptionEndDate.setFullYear(subscriptionEndDate.getFullYear() + 1);
            }

            try {
                // Begin transaction
                await query('BEGIN');

                console.log('Starting database transaction for premium update:', {
                    userId,
                    plan,
                    subscriptionEndDate,
                    amount
                });

                // Insert into premium_users table
                const insertResult = await query(
                    `INSERT INTO premium_users 
                    (user_id, plan_type, subscription_end_date, amount_paid) 
                    VALUES ($1, $2, $3, $4) 
                    RETURNING id`,
                    [userId, plan, subscriptionEndDate, amount]
                );

                console.log('Inserted into premium_users:', insertResult.rows[0]);

                // Update user's premium status
                const updateResult = await query(
                    'UPDATE users SET is_premium = true WHERE id = $1 RETURNING id, username, is_premium',
                    [userId]
                );

                console.log('Updated user premium status:', updateResult.rows[0]);

                // Commit transaction
                await query('COMMIT');

                console.log('Successfully completed premium update transaction');
                res.json({ 
                    success: true,
                    message: 'Premium subscription activated successfully',
                    details: {
                        plan: plan,
                        endDate: subscriptionEndDate,
                        isPremium: true
                    }
                });
                isPremium = true;
            } catch (dbError) {
                // Rollback transaction on error
                await query('ROLLBACK');
                console.error('Database error during premium update:', dbError);
                res.status(500).json({ 
                    success: false, 
                    error: 'Database error while updating premium status',
                    details: dbError.message
                });
            }
        } else {
            console.error('Signature verification failed:', {
                expected: expectedSignature,
                received: razorpay_signature
            });
            res.status(400).json({ 
                success: false, 
                error: 'Invalid payment signature',
                details: 'Payment verification failed'
            });
        }
    } catch (error) {
        console.error('Error in payment verification:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error verifying payment',
            details: error.message
        });
    }
});

// Premium Page Route
app.get("/premium", async (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }

    try {
        // Get user details including premium status
        const userResult = await query(
            "SELECT * FROM users WHERE username = $1",
            [req.session.username]
        );
        
        if (userResult.rows.length === 0) {
            return res.redirect("/login");
        }

        const user = userResult.rows[0];

        // Check for active subscription and update premium status
        const subscriptionResult = await query(
            `SELECT plan_type, subscription_end_date 
            FROM premium_users 
            WHERE user_id = $1 
            AND subscription_end_date > CURRENT_TIMESTAMP 
            ORDER BY subscription_end_date DESC 
            LIMIT 1`,
            [user.id]
        );

        // Update user's premium status based on subscription
        const hasActiveSubscription = subscriptionResult.rows.length > 0;
        if (user.is_premium !== hasActiveSubscription) {
            await query(
                'UPDATE users SET is_premium = $1 WHERE id = $2',
                [hasActiveSubscription, user.id]
            );
            user.is_premium = hasActiveSubscription;
        }

        let subscriptionDetails = hasActiveSubscription ? subscriptionResult.rows[0] : null;

        res.render("premium", {
            user: {
                ...user,
                username: req.session.username,
                is_premium: user.is_premium
            },
            subscriptionDetails
        });
    } catch (err) {
        console.error("Error loading premium page:", err);
        res.status(500).send("Error loading premium page");
    }
});

// Premium Page Route
app.get("/premium", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }
    res.render("premium", {
        user: {
            username: req.session.username
        }
    });
});
// Logout Route
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
        }
        res.redirect("/login");
    });
});

// Profile Routes
app.get("/profile", async (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }

    try {
        // Get user details
        const userResult = await query(
            "SELECT * FROM users WHERE username = $1",
            [req.session.username]
        );
        
        if (userResult.rows.length === 0) {
            return res.redirect("/login");
        }

        const user = userResult.rows[0];

        // Get subscription details
        const subscriptionResult = await query(
            `SELECT plan_type, subscription_end_date 
            FROM premium_users 
            WHERE user_id = $1 
            AND subscription_end_date > CURRENT_TIMESTAMP 
            ORDER BY subscription_end_date DESC 
            LIMIT 1`,
            [req.session.userId]
        );

        // Get liked songs count
        const likedSongsResult = await query(
            "SELECT COUNT(*) FROM liked WHERE userid = $1",
            [req.session.userId]
        );
        const likedSongsCount = likedSongsResult.rows[0].count;

        // Get playlists count - Fixed column name from userid to user_id
        const playlistsResult = await query(
            "SELECT COUNT(*) FROM playlists WHERE user_id = $1",
            [req.session.userId]
        );
        const playlistsCount = playlistsResult.rows[0].count;

        res.render("profile", {
            user,
            likedSongsCount,
            playlistsCount,
            error: req.query.error,
            success: req.query.success,
            subscriptionDetails: subscriptionResult.rows[0] || null
        });
    } catch (err) {
        console.error("Error fetching profile data:", err);
        res.render("profile", {
            user: { username: req.session.username },
            error: "Error loading profile data",
            likedSongsCount: 0,
            playlistsCount: 0,
            subscriptionDetails: null
        });
    }
});

// Update username route
app.post("/update-username", async (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login");
    }

    const { newUsername } = req.body;
    
    try {
        // Check if username is already taken
        const existingUser = await query(
            "SELECT * FROM users WHERE username = $1 AND username != $2",
            [newUsername, req.session.username]
        );

        if (existingUser.rows.length > 0) {
            return res.redirect("/profile?error=username_taken");
        }

        // Update username
        await query(
            "UPDATE users SET username = $1 WHERE username = $2",
            [newUsername, req.session.username]
        );

        // Update session
        req.session.username = newUsername;

        res.redirect("/profile?success=true");
    } catch (err) {
        console.error("Error updating username:", err);
        res.redirect("/profile?error=update_failed");
    }
});

app.post("/update-profile", async (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    try {
        const { username, email } = req.body;

        // Check if username or email is already taken by another user
        const existingUser = await query(
            "SELECT * FROM users WHERE (username = $1 OR email = $2) AND id != $3",
            [username, email, req.session.userId]
        );

        if (existingUser.rows.length > 0) {
            return res.render("profile", {
                error: true,
                errorMessage: "Username or email already taken",
                user: { username, email }
            });
        }

        // Update user profile
        await query(
            "UPDATE users SET username = $1, email = $2 WHERE id = $3",
            [username, email, req.session.userId]
        );

        // Update session
        req.session.username = username;

        res.redirect("/profile");
    } catch (err) {
        console.error("Error updating profile:", err);
        res.status(500).send("Error updating profile");
    }
});

app.post("/change-password", async (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;

        // Verify current password
        const user = await query("SELECT * FROM users WHERE id = $1", [req.session.userId]);
        if (user.rows.length === 0) {
            return res.redirect("/login");
        }

        const validPassword = await bcrypt.compare(currentPassword, user.rows[0].password);
        if (!validPassword) {
            return res.render("profile", {
                error: true,
                errorMessage: "Current password is incorrect",
                user: user.rows[0]
            });
        }

        // Check if new passwords match
        if (newPassword !== confirmPassword) {
            return res.render("profile", {
                error: true,
                errorMessage: "New passwords do not match",
                user: user.rows[0]
            });
        }

        // Hash and update new password
        const hashedPassword = await bcrypt.hash(newPassword, saltrounds);
        await query(
            "UPDATE users SET password = $1 WHERE id = $2",
            [hashedPassword, req.session.userId]
        );

        res.redirect("/profile");
    } catch (err) {
        console.error("Error changing password:", err);
        res.status(500).send("Error changing password");
    }
});

// Search page route
app.get("/search-page", (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }
    
    const playlistId = req.query.playlistId;
    const playlistName = req.query.playlistName;
    
    res.render("search", {
        user: req.session.username,
        playlistId: playlistId,
        playlistName: playlistName
    });
});

app.get("/add-to-playlist/:title", async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, error: "User not authenticated" });
    }
    
    try {
        const title = req.params.title;
        const playlistName = req.session.playlistName;
        const userId = req.session.userId;
        if (!playlistName) {
            return res.status(400).json({ success: false, error: "No playlist selected" });
        }
        
        // Get the song ID
        const songResult = await query("SELECT id FROM songs WHERE title = $1", [title]);
        if (songResult.rows.length === 0) {
            return res.status(404).json({ success: false, error: "Song not found" });
        }
        const songId = songResult.rows[0].id;
        
        // Get the playlist ID
        const playlistResult = await query(
            "SELECT id FROM playlists WHERE playlist_name = $1 AND user_id = $2", 
            [playlistName, userId]
        );
        if (playlistResult.rows.length === 0) {
            return res.status(404).json({ success: false, error: "Playlist not found" });
        }
        const playlistId = playlistResult.rows[0].id;
        
        // Check if the song is already in the playlist
        const existingSong = await query(
            "SELECT * FROM playlists WHERE id = $1 AND song_id = $2",
            [playlistId, songId]
        );
        
        if (existingSong.rows.length > 0) {
            return res.status(400).json({ success: false, error: "Song is already in this playlist" });
        }
        
        // Add the song to the playlist
        await query(
            "INSERT INTO playlists (playlist_name, user_id, song_id) VALUES ($1, $2, $3)",
            [playlistName, userId, songId]
        );
        
        // Redirect back to the search page
        res.redirect("/search-page");
    } catch (err) {
        console.error("Error adding song to playlist:", err);
        res.status(500).json({ success: false, error: "Internal server error" });
    }
});
// Route to get song ID by title
app.get("/get-song-id", async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, error: "User not authenticated" });
    }
    
    try {
        const title = req.query.title;
        if (!title) {
            return res.status(400).json({ success: false, error: "Title parameter is required" });
        }
        
        const lowercaseTitle = title.toLowerCase();
        const result = await query("SELECT id FROM songs WHERE title = $1", [lowercaseTitle]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: "Song not found" });
        }
        
        res.json({ success: true, songId: result.rows[0].id });
    } catch (err) {
        console.error("Error getting song ID:", err);
        res.status(500).json({ success: false, error: "Internal server error" });
    }
});

// Route to add a song to a playlist
app.post("/add-to-playlist", async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, error: "User not authenticated" });
    }
    
    try {
        const { playlistId, songId } = req.body;
        
        if (!playlistId || !songId) {
            return res.status(400).json({ success: false, error: "Playlist ID and Song ID are required" });
        }
        
        // Verify the playlist belongs to the user
        const playlistCheck = await query(
            "SELECT * FROM playlists WHERE id = $1 AND user_id = $2",
            [playlistId, req.session.userId]
        );
        
        if (playlistCheck.rows.length === 0) {
            return res.status(403).json({ success: false, error: "You don't have permission to add to this playlist" });
        }
        
        // Check if the song is already in the playlist
        const existingSong = await query(
            "SELECT * FROM playlists WHERE id = $1 AND song_id = $2",
            [playlistId, songId]
        );
        
        if (existingSong.rows.length > 0) {
            return res.status(400).json({ success: false, error: "Song is already in this playlist" });
        }
        
        // Add the song to the playlist
        await query(
            "INSERT INTO playlists (playlist_name, user_id, song_id) VALUES ($1, $2, $3)",
            [playlistName, req.session.userId, songId]
        );
        
        res.json({ success: true, message: "Song added to playlist successfully" });
    } catch (err) {
        console.error("Error adding song to playlist:", err);
        res.status(500).json({ success: false, error: "Internal server error" });
    }
});

// Route to get a random song from a specific playlist
app.get("/playlist-rand", async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: "User not authenticated" });
    }

    try {
        const playlistName = req.query.playlist;
        if (!playlistName) {
            return res.status(400).json({ error: "Playlist name is required" });
        }

        // Get a random song from the specified playlist
        const result = await query(`
            SELECT s.title, s.artist, s.cover, s.song 
            FROM playlists p 
            JOIN songs s ON p.song_id = s.id 
            WHERE p.playlist_name = $1 AND p.user_id = $2 
            ORDER BY RANDOM() 
            LIMIT 1
        `, [playlistName, req.session.userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "No songs found in playlist" });
        }

        const songdet = result.rows[0];

        // Convert image and audio from `bytea` to Base64
        const imageBase64 = `data:image/jpeg;base64,${songdet.cover.toString("base64")}`;
        const audioBase64 = `data:audio/mpeg;base64,${songdet.song.toString("base64")}`;

        // Increment played_times before checking for ad
        played_times++;
        
        // Check if it's time to show an ad (every 5 clicks) and user is not premium
        const shouldShowAd = !isPremium && played_times % 5 === 0;
        const currentAd = shouldShowAd ? getNextAd() : null;

        // Send response with song details and ad info
        res.json({
            title: songdet.title,
            artist: songdet.artist,
            image: imageBase64,
            audio: audioBase64,
            showAd: shouldShowAd,
            ad: currentAd
        });
    } catch (err) {
        console.error("Error getting random song from playlist:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Route to get a random song from a specific mood
app.get("/mood-rand", async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: "User not authenticated" });
    }

    try {
        const mood = req.query.mood;
        if (!mood) {
            return res.status(400).json({ error: "Mood parameter is required" });
        }

        // Get a random song from the specified mood
        const result = await query(`
            SELECT title, artist, cover, song 
            FROM songs 
            WHERE mood = $1 
            ORDER BY RANDOM() 
            LIMIT 1
        `, [mood]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "No songs found for this mood" });
        }

        const songdet = result.rows[0];

        // Convert image and audio from `bytea` to Base64
        const imageBase64 = `data:image/jpeg;base64,${songdet.cover.toString("base64")}`;
        const audioBase64 = `data:audio/mpeg;base64,${songdet.song.toString("base64")}`;

        // Increment played_times before checking for ad
        played_times++;
        
        // Check if it's time to show an ad (every 5 clicks) and user is not premium
        const shouldShowAd = !isPremium && played_times % 5 === 0;
        const currentAd = shouldShowAd ? getNextAd() : null;

        // Send response with song details and ad info
        res.json({
            title: songdet.title,
            artist: songdet.artist,
            image: imageBase64,
            audio: audioBase64,
            showAd: shouldShowAd,
            ad: currentAd
        });
    } catch (err) {
        console.error("Error getting random song from mood:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/mark-feedback-read", isAdmin, async (req, res) => {
    try {
        const { feedbackId } = req.body;
        
        await query("UPDATE feedback SET is_read = true WHERE id = $1", [feedbackId]);
        
        res.json({ success: true });
    } catch (error) {
        console.error("Error marking feedback as read:", error);
        res.status(500).json({ success: false, error: "Error marking feedback as read" });
    }
});

// Feedback routes
app.get("/feedback", async (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }
    
    try {
        const username = req.session.username;
        res.render("feedback", { username });
    } catch (error) {
        console.error("Error rendering feedback page:", error);
        res.status(500).send("Error loading feedback page");
    }
});

app.post("/submit-feedback", async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send("Unauthorized");
    }
    
    try {
        const { username, name, email, subject, message } = req.body;
        
        await query(
            "INSERT INTO feedback (username, name, email, subject, message) VALUES ($1, $2, $3, $4, $5)",
            [username, name, email, subject, message]
        );
        
        res.redirect("/feedback?success=true");
    } catch (error) {
        console.error("Error submitting feedback:", error);
        res.status(500).send("Error submitting feedback");
    }
});

// Error handler middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ 
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).render('error', {
        error: 'Page not found'
    });
});

// Test route
app.get("/test", (req, res) => {
    res.send("Server is working!");
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

// Export the Express API
export default app;