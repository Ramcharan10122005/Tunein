--Open pg admin--
--create a new database Tunein and then create the tables--
--User's Table--
CREATE TABLE users (
    id SERIAL PRIMARY KEY, 
    username VARCHAR(255) UNIQUE NOT NULL, 
    email VARCHAR(255) UNIQUE NOT NULL, 
    password TEXT NOT NULL
);
