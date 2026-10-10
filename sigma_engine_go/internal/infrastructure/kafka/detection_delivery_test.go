package kafka

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/edr-platform/sigma-engine/internal/application/alert"
	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/mapping"
	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/application/rulesync"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/cache"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type deliveryWriter struct{ entered, release chan struct{} }

func (w *deliveryWriter) Persist(ctx context.Context, a *domain.Alert) (string, bool, error) {
	close(w.entered)
	select {
	case <-ctx.Done():
		return "", false, ctx.Err()
	case <-w.release:
	}
	a.ID = "canonical-alert"
	return a.ID, true, nil
}
func (*deliveryWriter) UpdateCorrelationSummary(context.Context, string, map[string]any) error {
	return nil
}
func (*deliveryWriter) Metrics() database.AlertWriterMetrics { return database.AlertWriterMetrics{} }

type deliveryProducer struct {
	entered, release chan struct{}
	id               string
}

func (*deliveryProducer) Start(context.Context) error { return nil }
func (*deliveryProducer) Stop() error                 { return nil }
func (*deliveryProducer) Metrics() ProducerMetrics    { return ProducerMetrics{} }
func (p *deliveryProducer) PublishSync(ctx context.Context, a *domain.Alert) error {
	p.id = a.ID
	close(p.entered)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.release:
		return nil
	}
}

func TestDetectionWorkerAcknowledgesOnlyAfterDurableDelivery(t *testing.T) {
	rule, err := rules.NewRuleParser(false).ParseContent("title: Synthetic persistence boundary\nid: persistence-boundary\nstatus: stable\nlevel: high\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '\\malicious.exe'\n  condition: selection\n")
	require.NoError(t, err)
	fc, err := cache.NewFieldResolutionCache(64)
	require.NoError(t, err)
	engine := detection.NewSigmaDetectionEngine(mapping.NewFieldMapper(fc), detection.NewModifierRegistry(nil), fc, detection.QualityConfig{MinConfidence: .6})
	require.NoError(t, engine.LoadRules([]*domain.SigmaRule{rule}))
	ev, err := domain.NewLogEvent(map[string]interface{}{"event_type": "process", "agent_id": "agent", "data": map[string]interface{}{"executable": `C:\Temp\malicious.exe`}})
	require.NoError(t, err)
	assertDurableWorkerDelivery(t, engine, ev)
}

func TestLocalDiscoveryDurableDelivery(t *testing.T) {
	for _, tc := range []struct {
		file, kind string
		data       map[string]interface{}
	}{
		{"mitras_proc_local_account_discovery.yml", "process", map[string]interface{}{"executable": `C:\Windows\System32\net.exe`, "command_line": "net user"}},
		{"mitras_ps_local_account_discovery.yml", "powershell", map[string]interface{}{"event_code": 4104, "action": "script_block", "script_block_text": "Get-LocalUser"}},
		{"mitras_pm_local_account_discovery.yml", "powershell", map[string]interface{}{"event_code": 4103, "action": "module", "payload": "CommandInvocation(Get-LocalUser)"}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			r, err := rules.NewRuleParser(false).ParseFile(filepath.Join("../../../sigma_rules/rules/edr_custom", tc.file))
			require.NoError(t, err)
			canonical, err := rules.MarshalSigmaRule(r)
			require.NoError(t, err)
			legacy, err := yaml.Marshal(r)
			require.NoError(t, err)
			for name, content := range map[string][]byte{"canonical": canonical, "legacy": legacy} {
				t.Run(name, func(t *testing.T) {
					storedRule, err := rulesync.Parse(&database.Rule{ID: r.ID, Content: string(content)})
					require.NoError(t, err)
					fc, err := cache.NewFieldResolutionCache(64)
					require.NoError(t, err)
					engine := detection.NewSigmaDetectionEngine(mapping.NewFieldMapper(fc), detection.NewModifierRegistry(nil), fc, detection.QualityConfig{MinConfidence: .6, EnableFilters: true, EnableContextValidation: true})
					require.NoError(t, engine.LoadRules([]*domain.SigmaRule{storedRule}))
					ev, err := domain.NewLogEvent(map[string]interface{}{"event_type": tc.kind, "agent_id": "agent-7c3842b2-4593-49a4-9c6a-46a5d50c756a", "data": tc.data})
					require.NoError(t, err)
					assertDurableWorkerDelivery(t, engine, ev)
				})
			}
		})
	}
}

func assertDurableWorkerDelivery(t *testing.T, engine *detection.SigmaDetectionEngine, ev *domain.LogEvent) {
	t.Helper()
	ack := make(chan struct{})
	ev.SetAck(func() { close(ack) })
	writer := &deliveryWriter{make(chan struct{}), make(chan struct{})}
	producer := &deliveryProducer{entered: make(chan struct{}), release: make(chan struct{})}
	consumer := &EventConsumer{eventChan: make(chan *domain.LogEvent, 1)}
	loop := &EventLoop{consumer: consumer, producer: producer, alertWriter: writer, detectionEngine: engine, alertGenerator: alert.NewAlertGenerator(), suppression: newSuppressionCache(time.Minute), metrics: &EventLoopMetrics{}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	consumer.eventChan <- ev
	close(consumer.eventChan)
	loop.workerWG.Add(1)
	done := make(chan struct{})
	go func() { loop.detectionWorker(ctx, 0); close(done) }()
	wait := func(ch <-chan struct{}) {
		t.Helper()
		select {
		case <-ch:
		case <-ctx.Done():
			t.Fatal("timed out waiting for delivery stage")
		}
	}
	wait(writer.entered)
	select {
	case <-ack:
		t.Fatal("ack before persistence")
	default:
	}
	close(writer.release)
	wait(producer.entered)
	require.Equal(t, "canonical-alert", producer.id)
	select {
	case <-ack:
		t.Fatal("ack before broker confirmation")
	default:
	}
	close(producer.release)
	wait(ack)
	wait(done)
}
