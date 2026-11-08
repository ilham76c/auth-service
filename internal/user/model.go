package user

import "time"

type User struct {
	ID              int
	UUID            string
	Username        string
	Firstname       string
	Lastname        string
	Email           *string
	PasswordHash    *string
	EmailVerifiedAt *time.Time
	IsActive        bool
}
