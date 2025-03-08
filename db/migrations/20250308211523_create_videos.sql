-- migrate:up
create table videos (
  id serial primary key,
  user_id int not null references users(id),
  title bytea not null,
  url varchar(255) not null unique,
  created_at timestamp default current_timestamp,
  updated_at timestamp default current_timestamp
);


-- migrate:down
drop table videos;
