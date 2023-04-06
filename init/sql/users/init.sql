CREATE TABLE roles (
  id SERIAL PRIMARY KEY,
  name VARCHAR NOT NULL,
  description TEXT
);

INSERT INTO roles (id, name, description) 
VALUES (1, 'default', 'Standard role'), 
(2, 'moderator', 'Can see all chats'), 
(3, 'admin', 'Can set roles to another users');

CREATE TABLE users (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  firstname VARCHAR NOT NULL,
  lastname VARCHAR NOT NULL,
  patronymic VARCHAR,
  password VARCHAR NOT NULL,
  email VARCHAR NOT NULL UNIQUE,
  role_id INT DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP,
  FOREIGN KEY (role_id) REFERENCES roles(id)
);