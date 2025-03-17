package main

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/sethvargo/go-retry"
)

func DoRetry[T any](ctx context.Context, action string, fn func(context.Context) (T, error)) (T, error) {
	var result T
	var err error
	log := zerolog.Ctx(ctx)

	b := retry.NewFibonacci(1 * time.Second)
	b = retry.WithMaxRetries(5, b)
	b = retry.WithCappedDuration(5*time.Minute, b)
	err = retry.Do(ctx, b, func(ctx context.Context) error {
		result, err = fn(ctx)
		if err != nil {
			log.Warn().Err(err).Str("action", action).Msg("Attempt failed, retrying")
			return retry.RetryableError(err)
		}
		return nil
	})
	return result, err
}

func DoRetryArr[T any](ctx context.Context, action string, fn func(context.Context) ([]T, error)) ([]T, error) {
	var result []T
	var err error
	log := zerolog.Ctx(ctx)

	b := retry.NewFibonacci(1 * time.Second)
	b = retry.WithMaxRetries(5, b)
	b = retry.WithCappedDuration(5*time.Minute, b)
	err = retry.Do(ctx, b, func(ctx context.Context) error {
		result, err = fn(ctx)
		if err != nil {
			log.Warn().Err(err).Str("action", action).Msg("Attempt failed, retrying")
			return retry.RetryableError(err)
		}
		return nil
	})
	return result, err
}

// truncateString은 문자열을 지정된 길이로 잘라내고 필요시 '...'를 붙입니다.
func truncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	return fmt.Sprintf("%s...", s[:maxLength-3])
}
