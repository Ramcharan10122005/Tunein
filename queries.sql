--Open pg admin--
--create a new database Tunein and then create the tables--
--User's Table--
CREATE TABLE users (
    id SERIAL PRIMARY KEY, 
    username VARCHAR(255) UNIQUE NOT NULL, 
    email VARCHAR(255) UNIQUE NOT NULL, 
    password TEXT NOT NULL
);
--Songs Table--
CREATE TABLE songs (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    artist VARCHAR(255) NOT NULL,
    duration INTERVAL NOT NULL,
    song BYTEA NOT NULL,
    cover BYTEA NOT NULL,
    language VARCHAR(50) NOT NULL,
    genre VARCHAR(50) NOT NULL,
    mood VARCHAR(50) NOT NULL
);
CREATE TABLE liked (
    id SERIAL PRIMARY KEY,
    songid INT NOT NULL,
    userid INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_user FOREIGN KEY (userid) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_song FOREIGN KEY (songid) REFERENCES songs(id) ON DELETE CASCADE
);



-- Playlist Songs Table (junction table for many-to-many relationship)
CREATE TABLE playlist_songs (
    id SERIAL PRIMARY KEY,
    playlistid INT NOT NULL,
    songid INT NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_playlist FOREIGN KEY (playlistid) REFERENCES playlists(id) ON DELETE CASCADE,
    CONSTRAINT fk_song_playlist FOREIGN KEY (songid) REFERENCES songs(id) ON DELETE CASCADE,
    UNIQUE(playlistid, songid) -- Prevents duplicate songs in a playlist
);
CREATE TABLE playlists (
    id SERIAL PRIMARY KEY,
    playlist_name TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    song_id INTEGER
);

-- Create feedback table
CREATE TABLE IF NOT EXISTS feedback (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    subject VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_read BOOLEAN DEFAULT FALSE
);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback(created_at);
CREATE INDEX IF NOT EXISTS idx_feedback_is_read ON feedback(is_read);




