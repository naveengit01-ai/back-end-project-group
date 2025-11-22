```python
CREATE TABLE details (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    firstname VARCHAR(50),
    lastname VARCHAR(50),
    address VARCHAR(200),
    email VARCHAR(100),
    ph_no VARCHAR(20),
    profile_photo VARCHAR(200),
    user_name VARCHAR(50),
    password VARCHAR(50),
    user_type ENUM('user','rider') NOT NULL
);
```

```python

CREATE TABLE clothes (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,

    -- Foreign key → user who donated
    user_id INT,

    cloth_type VARCHAR(100),
    quantity VARCHAR(50),
    cloth_condition VARCHAR(50),
    location VARCHAR(255),

    status VARCHAR(20) DEFAULT 'pending',

    otp VARCHAR(20),
    otp_expiry DATETIME,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Foreign key → rider who accepts the pickup
    rider_id INT,

    -- Foreign key constraints
    CONSTRAINT fk_user
        FOREIGN KEY (user_id) REFERENCES details(id)
        ON DELETE SET NULL ON UPDATE CASCADE,

    CONSTRAINT fk_rider
        FOREIGN KEY (rider_id) REFERENCES details(id)
        ON DELETE SET NULL ON UPDATE CASCADE
);

```

```python

CREATE TABLE rider_assign (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    trip_id INT,
    rider_id INT,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

```

```python
CREATE TABLE rider_assign (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    trip_id INT,
    rider_id INT,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ra_trip
        FOREIGN KEY (trip_id) REFERENCES clothes(id)
        ON DELETE CASCADE ON UPDATE CASCADE,

    CONSTRAINT fk_ra_rider
        FOREIGN KEY (rider_id) REFERENCES details(id)
        ON DELETE SET NULL ON UPDATE CASCADE
);

```

```python

CREATE TABLE trip_otp (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    trip_id INT,
    otp_code VARCHAR(10),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,

    CONSTRAINT fk_tripotp_trip
        FOREIGN KEY (trip_id) REFERENCES clothes(id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

```

```python
CREATE TABLE trips (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,

    user_id INT,
    food_type VARCHAR(100),
    quantity VARCHAR(50),
    price VARCHAR(20),
    provider_type VARCHAR(50),
    location VARCHAR(255),

    status VARCHAR(20) DEFAULT 'pending',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rejection_reason VARCHAR(255),

    rider_id INT,

    otp VARCHAR(20),
    otp_expiry DATETIME,

    CONSTRAINT fk_trip_user
        FOREIGN KEY (user_id) REFERENCES details(id)
        ON DELETE SET NULL ON UPDATE CASCADE,

    CONSTRAINT fk_trip_rider
        FOREIGN KEY (rider_id) REFERENCES details(id)
        ON DELETE SET NULL ON UPDATE CASCADE
);

```