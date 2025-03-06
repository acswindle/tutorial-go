-- name: GetUser :one
SELECT * FROM users
WHERE id = $1;

-- name: InsertUsers :one
INSERT INTO users (username,email,password,salt)
VALUES ($1,$2,$3,$4)
RETURNING id;
