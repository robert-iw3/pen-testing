package utils

func PTR[T any](v T) *T {
	return &v
}
