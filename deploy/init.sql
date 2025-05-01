CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users
(
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email      VARCHAR(256) NOT NULL,
    password   TEXT         NOT NULL,
    name       VARCHAR(100),
    created_at DATE             DEFAULT now(),
    updated_at DATE             DEFAULT now(),
    deleted_at DATE             DEFAULT NULL
);

CREATE TABLE devices
(
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID         NOT NULL,
    device_mac VARCHAR(100) NOT NULL,
    type       varchar(256),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
