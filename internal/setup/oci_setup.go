package setup

import (
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/config"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/oci"
)

// SetupOCIStreaming 는 설정을 읽어 OCI Streaming 프로듀서와 컨슈머를 초기화합니다.
func SetupOCIStreaming(cfg *config.Configuration) (*oci.Producer, *oci.Consumer) {
	if cfg == nil {
		return nil, nil
	}
	ociCfg := cfg.OCIStreaming
	if ociCfg.Endpoint == "" || ociCfg.Topic == "" {
		return nil, nil
	}
	producer := oci.NewProducer(ociCfg.Endpoint, ociCfg.Topic, ociCfg.Credentials)
	consumer := oci.NewConsumer(ociCfg.Endpoint, ociCfg.Topic, ociCfg.Credentials)
	return producer, consumer
}
