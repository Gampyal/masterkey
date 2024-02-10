 CREATE TABLE super_admin (
id SERIAL,
email varchar(40) NOT NULL,
first_name varchar(40) NOT NULL,
last_name varchar(40) NOT NULL,
user_id varchar(11) NOT NULL,
password varchar(64) NOT NULL,
salt varchar(64) NOT NULL,
phone_number varchar(14) NOT NULL,
PRIMARY KEY (email));


CREATE TABLE house_owners (
id SERIAL,
email varchar(40) NOT NULL,
first_name varchar(40) NOT NULL,
last_name varchar(40) NOT NULL,
phone_number varchar(14) NOT NULL,
PRIMARY KEY (email));




CREATE TABLE owners_credentials (
id SERIAL,
email varchar(40) NOT NULL,
unique_id varchar(11) NOT NULL,
password varchar(40) NOT NULL,
salt varchar(14) NOT NULL,
FOREIGN KEY (email) REFERENCES house_owners (email));




CREATE TABLE gates (
gate_unique_id SERIAL,
user_unique_id varchar(11) NOT NULL,
gpio_pin  integer NOT NULL);




