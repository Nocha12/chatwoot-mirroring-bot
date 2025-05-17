package config

import (
	"fmt"
	"sync"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"maunium.net/go/mautrix/id"
)

// AccountMappingManager는 Chatwoot 계정과 Matrix ID 간의 매핑을 관리하는 구조체입니다.
type AccountMappingManager struct {
	mappings       []*AccountMappingInfo                                                 // 전체 매핑 목록
	chatwootIDMap  map[int]*AccountMappingInfo                                           // Chatwoot 설정 ID별 매핑
	matrixIDMap    map[int]*AccountMappingInfo                                           // Matrix 아이덴티티 ID별 매핑
	chatwootAccMap map[chatwootapi.AccountID]map[chatwootapi.InboxID]*AccountMappingInfo // Chatwoot 계정 ID와 인박스 ID별 매핑
	matrixUIDMap   map[id.UserID]*AccountMappingInfo                                     // Matrix 사용자 ID별 매핑
	mux            sync.RWMutex                                                          // 동시성 제어를 위한 뮤텍스
}

// NewAccountMappingManager는 새 AccountMappingManager 인스턴스를 생성합니다.
func NewAccountMappingManager() *AccountMappingManager {
	return &AccountMappingManager{
		mappings:       make([]*AccountMappingInfo, 0),
		chatwootIDMap:  make(map[int]*AccountMappingInfo),
		matrixIDMap:    make(map[int]*AccountMappingInfo),
		chatwootAccMap: make(map[chatwootapi.AccountID]map[chatwootapi.InboxID]*AccountMappingInfo),
		matrixUIDMap:   make(map[id.UserID]*AccountMappingInfo),
	}
}

// AddMapping은 매핑 정보를 매니저에 추가합니다.
func (m *AccountMappingManager) AddMapping(mapping *AccountMappingInfo) {
	m.mux.Lock()
	defer m.mux.Unlock()

	// 이미 존재하면 업데이트
	for i, existing := range m.mappings {
		if existing.ID == mapping.ID {
			m.mappings[i] = mapping
			m.updateIndices(mapping)
			return
		}
	}

	// 새로운 매핑 추가
	m.mappings = append(m.mappings, mapping)
	m.updateIndices(mapping)
}

// 내부 인덱스 업데이트 함수
func (m *AccountMappingManager) updateIndices(mapping *AccountMappingInfo) {
	// 기본 인덱스 업데이트
	m.chatwootIDMap[mapping.ChatwootConfigID] = mapping
	m.matrixIDMap[mapping.MatrixIdentityID] = mapping

	// Chatwoot 계정/인박스 인덱스 업데이트
	if mapping.ChatwootConfig != nil {
		accountID := mapping.ChatwootConfig.AccountID
		inboxID := mapping.ChatwootConfig.InboxID

		if _, exists := m.chatwootAccMap[accountID]; !exists {
			m.chatwootAccMap[accountID] = make(map[chatwootapi.InboxID]*AccountMappingInfo)
		}
		m.chatwootAccMap[accountID][inboxID] = mapping
	}

	// Matrix 사용자 ID 인덱스 업데이트
	if mapping.MatrixConfig != nil {
		m.matrixUIDMap[mapping.MatrixConfig.UserID] = mapping
	}
}

// RemoveMapping은 매핑 정보를 매니저에서 제거합니다.
func (m *AccountMappingManager) RemoveMapping(id int) {
	m.mux.Lock()
	defer m.mux.Unlock()

	for i, mapping := range m.mappings {
		if mapping.ID == id {
			// 매핑 삭제 전에 인덱스에서 제거
			delete(m.chatwootIDMap, mapping.ChatwootConfigID)
			delete(m.matrixIDMap, mapping.MatrixIdentityID)

			if mapping.ChatwootConfig != nil {
				accountID := mapping.ChatwootConfig.AccountID
				inboxID := mapping.ChatwootConfig.InboxID
				if inboxMap, exists := m.chatwootAccMap[accountID]; exists {
					delete(inboxMap, inboxID)
					if len(inboxMap) == 0 {
						delete(m.chatwootAccMap, accountID)
					}
				}
			}

			if mapping.MatrixConfig != nil {
				delete(m.matrixUIDMap, mapping.MatrixConfig.UserID)
			}

			// 매핑 목록에서 제거
			m.mappings = append(m.mappings[:i], m.mappings[i+1:]...)
			return
		}
	}
}

// SetMappingStatus는 매핑의 활성화 상태를 변경합니다.
func (m *AccountMappingManager) SetMappingStatus(id int, isActive bool) error {
	m.mux.Lock()
	defer m.mux.Unlock()

	for i, mapping := range m.mappings {
		if mapping.ID == id {
			m.mappings[i].IsActive = isActive
			return nil
		}
	}
	return fmt.Errorf("ID %d에 해당하는 매핑을 찾을 수 없습니다", id)
}

// GetMappingByChatwootAccountAndInbox는 Chatwoot 계정 ID와 인박스 ID로 매핑을 찾습니다.
func (m *AccountMappingManager) GetMappingByChatwootAccountAndInbox(accountID chatwootapi.AccountID, inboxID chatwootapi.InboxID) *AccountMappingInfo {
	m.mux.RLock()
	defer m.mux.RUnlock()

	if inboxMap, exists := m.chatwootAccMap[accountID]; exists {
		if mapping, exists := inboxMap[inboxID]; exists {
			if mapping.IsActive {
				return mapping
			}
		}
	}
	return nil
}

// GetMappingByMatrixUserID는 Matrix 사용자 ID로 매핑을 찾습니다.
func (m *AccountMappingManager) GetMappingByMatrixUserID(userID id.UserID) *AccountMappingInfo {
	m.mux.RLock()
	defer m.mux.RUnlock()

	if mapping, exists := m.matrixUIDMap[userID]; exists && mapping.IsActive {
		return mapping
	}
	return nil
}

// GetMappingByChatwootConfigID는 Chatwoot 설정 ID로 매핑을 찾습니다.
func (m *AccountMappingManager) GetMappingByChatwootConfigID(configID int) *AccountMappingInfo {
	m.mux.RLock()
	defer m.mux.RUnlock()

	if mapping, exists := m.chatwootIDMap[configID]; exists && mapping.IsActive {
		return mapping
	}
	return nil
}

// GetMappingByMatrixIdentityID는 Matrix 아이덴티티 ID로 매핑을 찾습니다.
func (m *AccountMappingManager) GetMappingByMatrixIdentityID(identityID int) *AccountMappingInfo {
	m.mux.RLock()
	defer m.mux.RUnlock()

	if mapping, exists := m.matrixIDMap[identityID]; exists && mapping.IsActive {
		return mapping
	}
	return nil
}

// GetMatrixUserIDForChatwootAccount는 Chatwoot 계정 ID와 인박스 ID에 대응하는 Matrix 사용자 ID를 반환합니다.
func (m *AccountMappingManager) GetMatrixUserIDForChatwootAccount(accountID chatwootapi.AccountID, inboxID chatwootapi.InboxID) (id.UserID, error) {
	mapping := m.GetMappingByChatwootAccountAndInbox(accountID, inboxID)
	if mapping == nil || mapping.MatrixConfig == nil {
		return "", fmt.Errorf("chatwoot 계정(ID: %d, 인박스: %d)에 매핑된 Matrix 사용자를 찾을 수 없습니다", accountID, inboxID)
	}
	return mapping.MatrixConfig.UserID, nil
}

// GetChatwootAccountForMatrixUserID는 Matrix 사용자 ID에 대응하는 Chatwoot 계정 정보를 반환합니다.
func (m *AccountMappingManager) GetChatwootAccountForMatrixUserID(userID id.UserID) (*RuntimeChatwootConfig, error) {
	mapping := m.GetMappingByMatrixUserID(userID)
	if mapping == nil || mapping.ChatwootConfig == nil {
		return nil, fmt.Errorf("matrix 사용자 %s에 매핑된 Chatwoot 계정을 찾을 수 없습니다", userID)
	}
	return mapping.ChatwootConfig, nil
}

// GetAllActiveMappings는 모든 활성화된 매핑을 반환합니다.
func (m *AccountMappingManager) GetAllActiveMappings() []*AccountMappingInfo {
	m.mux.RLock()
	defer m.mux.RUnlock()

	var activeMappings []*AccountMappingInfo
	for _, mapping := range m.mappings {
		if mapping.IsActive {
			activeMappings = append(activeMappings, mapping)
		}
	}
	return activeMappings
}
