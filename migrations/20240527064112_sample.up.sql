CREATE TABLE users(
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    login TEXT,
    email TEXT,
    password TEXT,
    verified BOOLEAN NOT NULL,
    UNIQUE (login),
    UNIQUE (email)
);

CREATE TYPE credential_provider AS ENUM(
    'github'
);

CREATE TABLE federated_credentials(
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider credential_provider NOT NULL,
    subject_id TEXT NOT NULL,
    UNIQUE (subject_id, provider),
    PRIMARY KEY (user_id, provider)
);


