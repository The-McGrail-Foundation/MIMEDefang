CREATE TABLE greylist
(
    sender_host_ip VARCHAR(40)  NOT NULL,
    sender         VARCHAR(256) NOT NULL,
    recipient      VARCHAR(256) NOT NULL,
    first_received INTEGER      NOT NULL,
    last_received  INTEGER      NOT NULL,
    known_ip       SMALLINT     NOT NULL,
    PRIMARY KEY (sender, recipient, sender_host_ip)
);
