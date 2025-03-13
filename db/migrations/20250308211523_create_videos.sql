-- migrate:up
create table videos (
  id serial primary key,
  user_id int not null references users(id),
  title bytea not null,
  nonce bytea not null,
  url uuid not null default gen_random_uuid(),
  upload_complete boolean default false,
  created_at timestamp default current_timestamp,
  updated_at timestamp default current_timestamp
);


-- migrate:down
drop table videos;
