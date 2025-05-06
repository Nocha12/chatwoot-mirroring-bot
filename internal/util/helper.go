package util

// TruncateString은 문자열을 지정된 길이로 잘라내고 필요시 '...'를 붙입니다.
func TruncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}

	// 문자열이 너무 길면 "..."를 추가
	if maxLength <= 3 {
		return "..."
	}

	return s[:maxLength-3] + "..."
}
