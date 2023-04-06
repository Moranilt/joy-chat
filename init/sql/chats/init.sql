CREATE TABLE users (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  firstname VARCHAR NOT NULL,
  lastname VARCHAR,
  middlename VARCHAR,
  email VARCHAR,
  extra TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE chats (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  users_id UUID NOT NULL,
  a_users_id UUID,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (users_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE messages (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  chat_id UUID NOT NULL,
  users_id UUID,
  a_users_id UUID,
  body TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
  FOREIGN KEY (users_id) REFERENCES users(id) ON DELETE CASCADE
);