-- migrate:up
create table users (
  id serial primary key,
  username varchar(255) not null unique,
  email varchar(255) not null unique,
  password bytea  not null,
  salt bytea not null,
  created_at timestamp default current_timestamp,
  updated_at timestamp default current_timestamp
);


-- migrate:down
drop table users;
