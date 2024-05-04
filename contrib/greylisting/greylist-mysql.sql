CREATE TABLE greylist
(
    sender_host_ip VARCHAR(40)  NOT NULL,
    sender         VARCHAR(256) NOT NULL,
    recipient      VARCHAR(256) NOT NULL,
    first_received DATETIME     NOT NULL,
    last_received  DATETIME     NOT NULL,
    known_ip       TINYINT(1)   UNSIGNED NOT NULL,
    UNIQUE (sender, recipient, sender_host_ip)
);
