package util

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"github.com/sethvargo/go-retry"
)

// DoRetry는 함수 실행을 재시도하는 범용 헬퍼 함수입니다.
func DoRetry[T interface{}](ctx context.Context, action string, fn func(context.Context) (T, error)) (T, error) {
	var result T
	var err error
	log := zerolog.Ctx(ctx)

	b := retry.NewFibonacci(1 * time.Second)
	b = retry.WithMaxRetries(5, b)
	b = retry.WithCappedDuration(5*time.Minute, b)
	err = retry.Do(ctx, b, func(ctx context.Context) error {
		result, err = fn(ctx)
		if err != nil {
			log.Warn().Err(err).Str("action", action).Msg("실행 실패, 재시도 중")
			return retry.RetryableError(err)
		}
		return nil
	})
	return result, err
}

// DoRetryArr는 배열을 반환하는 함수에 대한 재시도 헬퍼 함수입니다.
func DoRetryArr[T interface{}](ctx context.Context, action string, fn func(context.Context) ([]T, error)) ([]T, error) {
	var result []T
	var err error
	log := zerolog.Ctx(ctx)

	b := retry.NewFibonacci(1 * time.Second)
	b = retry.WithMaxRetries(5, b)
	b = retry.WithCappedDuration(5*time.Minute, b)
	err = retry.Do(ctx, b, func(ctx context.Context) error {
		result, err = fn(ctx)
		if err != nil {
			log.Warn().Err(err).Str("action", action).Msg("실행 실패, 재시도 중")
			return retry.RetryableError(err)
		}
		return nil
	})
	return result, err
}
