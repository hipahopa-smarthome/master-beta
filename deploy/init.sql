CREATE
    EXTENSION IF NOT EXISTS "uuid-ossp";

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
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID         NOT NULL,
    description TEXT,
    device_mac  VARCHAR(100) NOT NULL,
    type        varchar(256),
    device_info JSONB,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE capabilities
(
    id          SERIAL PRIMARY KEY,
    device_id   UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    type        TEXT UNIQUE NOT NULL CHECK (type IN
                                            ('devices.capabilities.on_off', 'devices.capabilities.color_setting',
                                             'devices.capabilities.mode', 'devices.capabilities.range',
                                             'devices.capabilities.toggle')),
    retrievable BOOL        NOT NULL DEFAULT False,
    reportable  BOOL        NOT NULL DEFAULT False,
    parameters  json,
    state       json
);

CREATE TABLE properties
(
    id          SERIAL PRIMARY KEY,
    device_id   UUID NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    type        TEXT NOT NULL CHECK (type IN ('devices.properties.float', 'devices.properties.event')),
    retrievable BOOL NOT NULL DEFAULT True,
    reportable  BOOL NOT NULL DEFAULT False,
    parameters  json,
    state       json
);
