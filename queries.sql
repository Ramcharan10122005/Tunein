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
    cover BYTEA NOT NULL
);

