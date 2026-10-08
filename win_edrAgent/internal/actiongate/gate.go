// Package actiongate coordinates mutations from remote commands and local
// prevention in this agent process. Waiting observes the action's deadline.
package actiongate

import (
	"context"
	"sync"
)

type Gate struct{ token chan struct{} }

var Default = New()

func New() *Gate { return &Gate{token: make(chan struct{}, 1)} }

func (g *Gate) Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case g.token <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-g.token
			return nil, err
		}
		var once sync.Once
		return func() { once.Do(func() { <-g.token }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
