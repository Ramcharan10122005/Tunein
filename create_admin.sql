-- Create admin table
CREATE TABLE IF NOT EXISTS admin (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert admin user with hashed password (Ramcharan@8)
-- Note: The password is hashed using bcrypt with 10 salt rounds
INSERT INTO admin (username, password) 
VALUES ('Ramcharan', '$2b$10$YourHashedPasswordHere')
ON CONFLICT (username) DO NOTHING; 