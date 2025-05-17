---
description: golangci-lint를 통한 에러 예방 플로우
---

1. golangci-lint run ./... 실행
2. 사이드 이펙트를 고려하기 위한 관련된 최대한 많은 파일 탐색
3. 나오는 버그 수정
4. 모든 린트 에러 해결까지 반복