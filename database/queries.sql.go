// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: queries.sql

package database

import (
	"context"
)

const getUser = `-- name: GetUser :one
SELECT id, username, email, password, salt FROM users
WHERE id = $1
`

func (q *Queries) GetUser(ctx context.Context, id int32) (User, error) {
	row := q.db.QueryRow(ctx, getUser, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.Email,
		&i.Password,
		&i.Salt,
	)
	return i, err
}

const insertUsers = `-- name: InsertUsers :one
INSERT INTO users (username,email,password,salt)
VALUES ($1,$2,$3,$4)
RETURNING id
`

type InsertUsersParams struct {
	Username string
	Email    string
	Password []byte
	Salt     []byte
}

func (q *Queries) InsertUsers(ctx context.Context, arg InsertUsersParams) (int32, error) {
	row := q.db.QueryRow(ctx, insertUsers,
		arg.Username,
		arg.Email,
		arg.Password,
		arg.Salt,
	)
	var id int32
	err := row.Scan(&id)
	return id, err
}
