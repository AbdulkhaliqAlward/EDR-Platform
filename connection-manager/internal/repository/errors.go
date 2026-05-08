// Package repository provides common errors for repositories.
package repository

import "errors"

// Common repository errors.
var (
	// ErrNotFound is returned when a record is not found.
	ErrNotFound = errors.New("record not found")

	// ErrDuplicate is returned when a duplicate record exists.
	ErrDuplicate = errors.New("duplicate record")

	// ErrInvalidInput is returned for invalid input data.
	ErrInvalidInput = errors.New("invalid input")

	// ErrTokenAlreadyBuilt is returned by IncrementBuildCount when the
	// enrollment token has already been consumed for a binary build.
	// One token is allowed to produce exactly one agent binary.
	ErrTokenAlreadyBuilt = errors.New("enrollment token has already been used to build an agent binary")

	// ErrKeyBAlreadyServed is returned by ServeKeyB when the atomic CTE
	// finds no matching row — meaning the key half has already been served,
	// the token is revoked, expired, or does not exist.
	// The caller MUST return HTTP 410 Gone on this error.
	ErrKeyBAlreadyServed = errors.New("key_b has already been served or token is invalid")
)

