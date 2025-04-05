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

const app = express();
const port = 3000;
const saltrounds = 10;
env.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
    })
);

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
const db = new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
})
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
    (req, res) => {
        if (req.user) {
            req.session.username = req.user.username;
            req.session.userId = req.user.id;
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
    (req, res) => {
        if (req.user) {
            // Make sure to set the session username
            req.session.username = req.user.username;
            req.session.userId = req.user.id;
            console.log("Session after Google auth:", req.session); // Add this to debug
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
        const songs = await db.query("SELECT * FROM songs WHERE mood = $1", [mood]);

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
    passport.authenticate("local", (err, user, info) => {
      if (err) return next(err);
      if (!user) {
        return res.render("login", {
          error: true,
          errorType: "user-exists" || "",
          errorMessage: info.message,
        });
      }
      
      req.logIn(user, (err) => {
        if (err) return next(err);
        req.session.username = user.username;  // This line is already correct
        return res.redirect("/"); 
      });
    })(req, res, next);
});
// Password Reset
app.post("/reset", async (req, res) => {
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
        const user = await db.query("update users SET password = $1 WHERE email = $2", [hashedPassword, email]);
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
        const result = await db.query("SELECT id FROM songs WHERE title = $1", [lowercaseTitle]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Song not found" });
        }

        const songid = result.rows[0].id;
        const userid = req.session.userId;

        // ✅ Prevents duplicate likes
        await db.query(
            "INSERT INTO liked (songid, userid) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            [songid, userid]
        );

        res.json({ success: true, message: "Song liked successfully" });
    } catch (error) {
        console.error("Error liking song:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get("/admin", async (req, res) => {
    const result = await db.query("SELECT * FROM songs ORDER BY id DESC");
    res.render("add", { songs: result.rows });
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

        await db.query(
            "INSERT INTO songs (title, artist, duration, song, cover, language, genre, mood) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            [lowercaseTitle, lowercaseArtist, duration, songFile, coverFile, lowercaseLanguage, lowercaseGenre, lowercaseMood]
        );

        res.redirect("/admin");
    } catch (error) {
        console.error("Error inserting song:", error);
        res.status(500).send("Error saving the song");
    }
});
// Route for playlist 
app.get("/playlists", async(req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    try {
        const userId = req.session.userId;
        const playlistsResult = await db.query("SELECT * FROM playlists WHERE user_id = $1", [userId]);
        
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
    await db.query("INSERT INTO playlists (playlist_name, user_id) VALUES ($1, $2)", [name, req.session.userId]);
    res.redirect("/playlists");
})
// Route to display songs in a playlist
app.get("/playlists/songs", async (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    const playlistName = req.query.name;
    const loggedInUserId = req.session.userId;

    try {
        // Fetch all playlists and their songs for the logged-in user
        const playlistsResult = await db.query(`
            SELECT 
                p.id AS playlist_id,
                p.playlist_name AS playlist_name,
                p.user_id,
                u.username,
                s.title AS song_title,
                s.artist
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
                    userId: row.userid,
                    username: row.username,
                    name: row.playlist_name,
                    songs: []
                });
            }

            if (row.song_title && row.artist) {
                playlistsMap.get(key).songs.push({
                    name: row.song_title,
                    artist: row.artist
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

app.get("/song/:title", async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: "User not authenticated" });
    }
    try {
        const title = decodeURIComponent(req.params.title);
        const lowercaseTitle = title.toLowerCase();
        console.log(title); 
        const result = await db.query("SELECT title, artist, cover, song FROM songs WHERE title = $1", [lowercaseTitle]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Song not found" });
        }

        const songdet = result.rows[0];
        const imageBase64 = `data:image/jpeg;base64,${songdet.cover.toString("base64")}`;
        const audioBase64 = `data:audio/mpeg;base64,${songdet.song.toString("base64")}`;

        res.json({
            title: songdet.title,
            artist: songdet.artist,
            image: imageBase64,
            audio: audioBase64
        });
    } catch (err) {
        console.error("Error fetching song:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.get("/liked-songs", async (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    try {
        // Get all liked songs for the current user with song details
        const result = await db.query(`
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

app.get("/play/:title", async (req, res) => {
    try {
        const title = decodeURIComponent(req.params.title);
        const lowercaseTitle = title.toLowerCase();
        console.log(title);

        const result = await db.query("SELECT title, artist, cover, song FROM songs WHERE title = $1", [lowercaseTitle]);

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
            user:req.session.username
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});
passport.use(
    "local",
    new Strategy(async function verify(username, password, cb) {
      try {
        const result = await db.query("SELECT * FROM users WHERE username = $1", [
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
      callbackURL: "http://localhost:3000/auth/google/callback",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log("Google profile received:", profile); // Debug log
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.emails[0].value]);
        
        if(result.rows.length === 0) {
          // Create new user
          const newUser = await db.query(
            "INSERT INTO users(username, email, password) VALUES($1, $2, $3) RETURNING *",
            [profile.displayName, profile.emails[0].value, "google"]
          );
          return cb(null, {
            id: newUser.rows[0].id,
            username: profile.displayName,
            email: profile.emails[0].value
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
            callbackURL: "http://localhost:3000/auth/github/callback",
        },
        async (accessToken, refreshToken, profile, cb) => {
            try {
                console.log("GitHub profile received:", profile); // Debugging

                const email = profile.emails?.[0]?.value || ""; // Get email (if available)
                const username = profile.username || profile.displayName || "GitHubUser";

                // Check if user already exists in the database by email
                const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);

                if (result.rows.length === 0) {
                    // Insert new user into the database
                    const newUser = await db.query(
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
        const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
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
        const query = req.query.query;
        if (!query) {
            return res.json([]);
        }

        // Search in songs table by title, artist, language, genre, or mood
        const result = await db.query(
            "SELECT title, artist, cover, language, genre, mood FROM songs WHERE LOWER(title) LIKE LOWER($1) OR LOWER(artist) LIKE LOWER($1) OR LOWER(language) LIKE LOWER($1) OR LOWER(genre) LIKE LOWER($1) OR LOWER(mood) LIKE LOWER($1)",
            [`%${query}%`]
        );

        // Convert cover images to base64
        const songs = result.rows.map(song => ({
            title: song.title,
            artist: song.artist,
            image: `data:image/jpeg;base64,${song.cover.toString('base64')}`
        }));

        res.json(songs);
    } catch (err) {
        console.error('Error searching songs:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.post('/create-order', async (req, res) => {
    try {
        const { amount, currency } = req.body;
        
        // Validate required parameters
        if (!amount || !currency) {
            return res.status(400).json({ error: 'Amount and currency are required' });
        }
        
        // Initialize Razorpay with your credentials
        const razorpay = new Razorpay({
            key_id: process.env.RAZORPAY_KEY_ID,
            key_secret: process.env.RAZORPAY_KEY_SECRET
        });
        
        const options = {
            amount: amount,
            currency: currency,
            receipt: `receipt_${Date.now()}`,
        };
        
        const order = await razorpay.orders.create(options);
        res.json({ orderId: order.id });
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).render('error', { 
            error: 'Failed to create payment order. Please try again.' 
        });
    }
});

app.post('/verify-payment', async (req, res) => {
    try {
        const { razorpay_payment_id, razorpay_order_id, razorpay_signature, plan } = req.body;
        
        // Create the expected signature
        const body = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(body.toString())
            .digest('hex');

        // Verify the signature
        if (expectedSignature === razorpay_signature) {
            // Update user's premium status in the database
            const userId = req.session.userId;
            const subscriptionEndDate = new Date();
            
            // Set subscription end date based on plan
            if (plan === 'monthly') {
                subscriptionEndDate.setMonth(subscriptionEndDate.getMonth() + 1);
            } else if (plan === 'yearly') {
                subscriptionEndDate.setFullYear(subscriptionEndDate.getFullYear() + 1);
            } else if (plan === 'family') {
                subscriptionEndDate.setMonth(subscriptionEndDate.getMonth() + 1);
            }

            // Update user's premium status in the database
            await db.query(
                'UPDATE users SET is_premium = true, subscription_end_date = $1 WHERE id = $2',
                [subscriptionEndDate, userId]
            );

            res.json({ success: true });
        } else {
            res.status(400).json({ success: false, error: 'Invalid signature' });
        }
    } catch (error) {
        console.error('Error verifying payment:', error);
        res.status(500).json({ success: false, error: 'Error verifying payment' });
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
        const userResult = await db.query(
            "SELECT * FROM users WHERE username = $1",
            [req.session.username]
        );
        
        if (userResult.rows.length === 0) {
            return res.redirect("/login");
        }

        const user = userResult.rows[0];

        // Get liked songs count
        const likedSongsResult = await db.query(
            "SELECT COUNT(*) FROM liked WHERE userid = $1",
            [user.id]
        );
        const likedSongsCount = likedSongsResult.rows[0].count;

        // Get playlists count
        const playlistsResult = await db.query(
            "SELECT COUNT(*) FROM playlists WHERE userid = $1",
            [user.id]
        );
        const playlistsCount = playlistsResult.rows[0].count;

        res.render("profile", {
            user,
            likedSongsCount,
            playlistsCount,
            error: req.query.error,
            success: req.query.success
        });
    } catch (err) {
        console.error("Error fetching profile data:", err);
        res.render("profile", {
            user: { username: req.session.username },
            error: "Error loading profile data",
            likedSongsCount: 0,
            playlistsCount: 0
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
        const existingUser = await db.query(
            "SELECT * FROM users WHERE username = $1 AND username != $2",
            [newUsername, req.session.username]
        );

        if (existingUser.rows.length > 0) {
            return res.redirect("/profile?error=username_taken");
        }

        // Update username
        await db.query(
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
        const existingUser = await db.query(
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
        await db.query(
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
        const user = await db.query("SELECT * FROM users WHERE id = $1", [req.session.userId]);
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
        await db.query(
            "UPDATE users SET password = $1 WHERE id = $2",
            [hashedPassword, req.session.userId]
        );

        res.redirect("/profile");
    } catch (err) {
        console.error("Error changing password:", err);
        res.status(500).send("Error changing password");
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});

// Error handler middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(err.status || 500).render('error', {
        error: err.message || 'An unexpected error occurred'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).render('error', {
        error: 'Page not found'
    });
});
