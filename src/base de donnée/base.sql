CREATE DATABASE IF NOT EXISTS packet_analysis;

USE packet_analysis;

CREATE TABLE IF NOT EXISTS known_ports (
    port INT PRIMARY KEY,
    protocol VARCHAR(50)
);


CREATE TABLE IF NOT EXISTS new_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255),
    source_ip VARCHAR(50),
    source_port VARCHAR(50),
    destination_ip VARCHAR(50),
    destination_port VARCHAR(50),
    protocol VARCHAR(10),
    application_layer_protocol VARCHAR(50),
    prediction VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS blocked_frames (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255),
    source_ip VARCHAR(50),
    source_port VARCHAR(50),
    destination_ip VARCHAR(50),
    destination_port VARCHAR(50),
    protocol VARCHAR(10),
    application_layer_protocol VARCHAR(50),
    prediction VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS passed_frames (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255),
    source_ip VARCHAR(50),
    source_port VARCHAR(50),
    destination_ip VARCHAR(50),
    destination_port VARCHAR(50),
    protocol VARCHAR(10),
    application_layer_protocol VARCHAR(50),
    prediction VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS false_positive_frames (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255),
    source_ip VARCHAR(50),
    source_port VARCHAR(50),
    destination_ip VARCHAR(50),
    destination_port VARCHAR(50),
    protocol VARCHAR(10),
    application_layer_protocol VARCHAR(50),
    prediction VARCHAR(50)
);
