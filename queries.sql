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

-- Playlists Table
CREATE TABLE playlists (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    userid INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_playlist_user FOREIGN KEY (userid) REFERENCES users(id) ON DELETE CASCADE
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

