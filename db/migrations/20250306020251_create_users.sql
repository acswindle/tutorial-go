-- migrate:up
create table users (
  id serial primary key,
  username varchar(255) not null unique,
  email varchar(255) not null unique,
  password bytea  not null,
  salt bytea not null
);


-- migrate:down
drop table users;
