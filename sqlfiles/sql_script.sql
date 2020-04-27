/* create the database */
create database vulnerabilities;
use vulnerabilities;

/* Delete the tables if they already exist */
drop table if exists SUSE;
drop table if exists RedHat;
drop table if exists Advisory_CVEs;
drop table if exists CVE;
drop table if exists Products;

/* Create the schema for our tables */
create table CVE(
cve		        varchar(20) PRIMARY KEY,
severity	    decimal(1,1),
rating	        char(10),
published	    date NOT NULL,
description	    TEXT,
os              char(6) NOT NULL);

create table SUSE(
advID           varchar(50) PRIMARY KEY,
title           varchar(255),
severity        char(10),
published       date NOT NULL);

create table RedHat(
advID           varchar(50) PRIMARY KEY,
title           varchar(255),
severity        char(10),
published       date NOT NULL);

create table Product(
advID               varchar(50),
affected product    varchar(255));

create table Adv_CVE(
advID               varchar(50),
cve                 varchar(20));

create table Inventory(
mac                 varchar(32) NOT NULL PRIMARY KEY,
fqdn                varchar(255),
os                  char(6) NOT NULL,
computer_type       char(10),
product             varchar(75));



