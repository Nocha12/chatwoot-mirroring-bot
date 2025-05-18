---
description: go build -tags goolm -o chatwoot ./cmd/bot 를 통한 에러 해결 플로우
---

1. go build -tags goolm -o chatwoot ./cmd/bot 실행
2. golangci-lint run ./... 실행
3. 사이드 이펙트를 고려하기 위한 관련된 최대한 많은 파일 탐색
4. 나오는 버그 수정
5. 모든 빌드 에러 해결까지 반복
