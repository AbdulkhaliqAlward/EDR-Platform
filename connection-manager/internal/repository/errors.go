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

	// ErrBuildIDAlreadySet is returned by StoreBuildID when the atomic CAS
	// (WHERE build_id IS NULL) finds no row — meaning a BuildID has already
	// been assigned to this token. One token → one binary → one BuildID.
	ErrBuildIDAlreadySet = errors.New("build_id already set for this enrollment token")
)


