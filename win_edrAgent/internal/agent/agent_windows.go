//go:build windows
// +build windows

package agent

import (
	"context"
	"fmt"
	"github.com/edr-platform/win-agent/internal/command"

	"github.com/edr-platform/win-agent/internal/collectors"
	"github.com/edr-platform/win-agent/internal/responder"
	"github.com/edr-platform/win-agent/internal/signatures"
)

// startPlatformCollectors starts Windows-specific collectors (ETW, Registry, Network, WMI) when enabled.
// Each collector runs in its own goroutine and respects ctx.Done() for graceful shutdown.
// A shared telemetry filter is built from cfg.Filtering to reduce noise (ExcludePaths, ExcludeIPs, etc.).
// Panics in collector goroutines are recovered so one failing collector cannot crash the agent.
func startPlatformCollectors(ctx context.Context, a *Agent) {
	if a == nil || a.cfg == nil || a.logger == nil || a.eventChan == nil {
		return
	}
	cfg := a.cfg
	logger := a.logger
	eventChan := a.eventChan

	var fileAuto collectors.FileAutoResponse
	var processAuto collectors.ProcessAutoResponse
	dbPath := cfg.Response.SignatureDBPath
	if dbPath == "" {
		dbPath = `C:\ProgramData\EDR\signatures.db`
	}
	st, err := signatures.Open(dbPath)
	if err != nil {
		logger.Warnf("[Response] signature database unavailable (auto-quarantine / C2 UPDATE_SIGNATURES / feeds disabled): %v", err)
	} else {
		a.commandHandler.SetSignatureStore(st)
		a.heartbeat.SetSignatureVersionProvider(func() int64 {
			v, err := st.GetServerVersion()
			if err != nil {
				return 0
			}
			return v
		})
		go func() {
			<-ctx.Done()
			_ = st.Close()
		}()
		if cfg.Response.AutoQuarantine && cfg.Collectors.FileEnabled && cfg.Collectors.ETWEnabled {
			maxB := cfg.Response.MaxScanBytes
			if maxB <= 0 {
				maxB = 10 << 20
			}
			eng := responder.NewEngine(logger, st, `C:\ProgramData\EDR\quarantine`, maxB, true)
			fileAuto = eng
			a.commandHandler.SetQuarantineRestorer(eng)
			if cfg.Response.USBWatcher {
				go collectors.StartUSBVolumeWatcher(ctx, eng, logger)
			}
			logger.Info("[Response] Local signature DB opened; autonomous file response armed")
		} else {
			logger.Info("[Response] Local signature DB opened (C2 UPDATE_SIGNATURES / optional auto-fetch; auto-quarantine inactive — ETW/file off or auto_quarantine false)")
		}
		if cfg.Response.ProcessAutoKillEnabled && cfg.Collectors.ETWEnabled {
			rulesPath := cfg.Response.ProcessRulesPath
			if rulesPath == "" {
				rulesPath = `C:\ProgramData\EDR\process_prevention_rules.json`
			}
			if err := responder.EnsureDefaultProcessRulesFile(rulesPath, logger); err != nil {
				logger.Warnf("[Response] Default process rules could not be provisioned: %v", err)
			}
			mode := cfg.Response.ProcessPreventionMode
			if mode == "" {
				mode = "auto_kill_then_override"
			}
			peng, pErr := responder.NewProcessEngine(logger, rulesPath, mode, true)
			if pErr != nil {
				logger.Warnf("[Response] process auto-response disabled: %v", pErr)
			} else {
				peng.SetTerminator(func(actionCtx context.Context, params map[string]string) (string, error) {
					res := a.commandHandler.Execute(actionCtx, &command.Command{
						ID:   "local-prevention-" + params["pid"] + "-" + params["process_started_at"],
						Type: command.CmdTerminateProcess, Parameters: params,
					})
					if res.Status != "SUCCESS" {
						return res.Output, fmt.Errorf("%s", res.Error)
					}
					return res.Output, nil
				})
				processAuto = peng
				logger.Infof("[Response] Process auto-response armed (mode=%s rules=%s)", mode, rulesPath)
			}
		}
		if cfg.Response.SignatureAutoFetchEnabled {
			feedURL := cfg.Response.SignatureAutoFetchURL
			if feedURL == "" {
				feedURL = signatures.DefaultMalwareBazaarRecentURL
			}
			lim := cfg.Response.SignatureAutoFetchLimit
			iv := cfg.Response.SignatureAutoFetchInterval
			force := cfg.Response.SignatureAutoFetchForce
			go signatures.StartPublicFeedAutoFetch(ctx, st, logger, feedURL, iv, lim, force)
			logger.Infof("[Response] Public signature auto-fetch enabled (interval=%v limit=%d url=%s)", iv, lim, feedURL)
		}
		if cfg.Response.SignatureServerSyncEnabled {
			serverFeedURL := cfg.Response.SignatureServerSyncURL
			if serverFeedURL == "" {
				// Auto-construct from server address: assume the HTTP port is the same
				// host as gRPC but served on the API port (Connection Manager default 8082).
				// Operators can override via SignatureServerSyncURL in config.
				serverFeedURL = "https://" + cfg.Server.Address + "/api/v1/signatures/feed.ndjson"
			}
			iv := cfg.Response.SignatureServerSyncInterval
			go signatures.StartServerFeedAutoFetch(ctx, st, logger, serverFeedURL, iv)
			logger.Infof("[Response] Server signature sync enabled (interval=%v url=%s)", iv, serverFeedURL)
		}
	}

	// Global telemetry filter from config
	evtFilter := collectors.NewFilter(collectors.FilterConfig{
		ExcludeProcesses: cfg.Filtering.ExcludeProcesses,
		ExcludeIPs:       cfg.Filtering.ExcludeIPs,
		ExcludeRegistry:  cfg.Filtering.ExcludeRegistry,
		ExcludePaths:     cfg.Filtering.ExcludePaths,
		IncludePaths:     cfg.Filtering.IncludePaths,
		ExcludeEventIDs:  cfg.Filtering.ExcludeEventIDs,
		TrustedHashes:    cfg.Filtering.TrustedHashes,
	}, logger)

	// ETW collector (process events + optional file I/O + image load)
	// All three event types share a single kernel session for minimal overhead.
	if cfg.Collectors.ETWEnabled {
		sessionName := cfg.Collectors.ETWSessionName
		if sessionName == "" {
			sessionName = "EDRAgentSession"
		}
		etw := collectors.NewETWCollector(
			sessionName, eventChan, logger, evtFilter,
			cfg.Collectors.FileEnabled,
			cfg.Collectors.ImageLoadEnabled,
		)
		if fileAuto != nil {
			etw.SetFileAutoResponse(fileAuto)
		}
		if processAuto != nil {
			etw.SetProcessAutoResponse(processAuto)
		}
		a.RegisterDropSource("etw", func() uint64 { return etw.Stats().EventsDropped })
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("ETW collector panicked and was safely recovered: %v", r)
				}
			}()
			if err := etw.Start(ctx); err != nil {
				logger.Warnf("ETW collector failed to start: %v", err)
			} else {
				logger.Info("ETW collector started")
			}
		}()

		// Phase 1: Named Pipe monitoring (piggybacks on kernel ETW FileIo session)
		// Pipe events are intercepted from the FileIo stream when paths contain
		// \Device\NamedPipe\. This is a lightweight in-process filter with NO
		// additional ETW session overhead.
		if cfg.Collectors.PipeEnabled {
			pipe := collectors.NewPipeCollector(eventChan, logger)
			pipe.Enable()
			logger.Info("Named Pipe collector enabled (via kernel FileIo ETW)")
		} else {
			logger.Debug("Named Pipe collector disabled by config")
		}
	} else {
		logger.Debug("ETW collector disabled by config")
	}

	// Registry collector (persistence / config change monitoring)
	if cfg.Collectors.RegistryEnabled {
		reg := collectors.NewRegistryCollector(eventChan, evtFilter, logger)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Registry collector panicked and was safely recovered: %v", r)
				}
			}()
			if err := reg.Start(ctx); err != nil {
				logger.Warnf("Registry collector failed to start: %v", err)
			} else {
				logger.Info("Registry collector started")
			}
		}()
	} else {
		logger.Debug("Registry collector disabled by config")
	}

	// Network collector (connection monitoring)
	if cfg.Collectors.NetworkEnabled {
		net := collectors.NewNetworkCollector(eventChan, evtFilter, cfg.Filtering.FilterPrivateNetworks, logger)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Network collector panicked and was safely recovered: %v", r)
				}
			}()
			if err := net.Start(ctx); err != nil {
				logger.Warnf("Network collector failed to start: %v", err)
			} else {
				logger.Info("Network collector started")
			}
		}()
	} else {
		logger.Debug("Network collector disabled by config")
	}

	// WMI collector (inventory / periodic system events)
	if cfg.Collectors.WMIEnabled {
		interval := cfg.Collectors.WMIInterval
		wmi := collectors.NewWMICollector(interval, eventChan, logger)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("WMI collector panicked and was safely recovered: %v", r)
				}
			}()
			if err := wmi.Start(ctx); err != nil {
				logger.Warnf("WMI collector failed to start: %v", err)
			} else {
				logger.Info("WMI collector started")
			}
		}()
	} else {
		logger.Debug("WMI collector disabled by config")
	}

	// =====================================================================
	// Phase 1: New User-Mode ETW Collectors (DNS, Process Access)
	// These run in SEPARATE ETW sessions from the kernel trace because
	// they are manifest-based providers, not kernel trace flags.
	// =====================================================================

	// DNS collector (Microsoft-Windows-DNS-Client via ETW)
	// Enables 50+ Sigma dns_query rules for C2/DGA/tunneling detection.
	if cfg.Collectors.DNSEnabled {
		dns := collectors.NewDNSCollector(eventChan, logger)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("DNS collector panicked and was safely recovered: %v", r)
				}
			}()
			if err := dns.Start(ctx); err != nil {
				logger.Warnf("DNS collector failed to start: %v", err)
			} else {
				logger.Info("DNS collector started")
			}
		}()
	} else {
		logger.Debug("DNS collector disabled by config")
	}

	// Process Access collector (Microsoft-Windows-Kernel-Audit-API-Calls via ETW)
	// Detects credential dumping (Mimikatz), process injection, and handle abuse.
	if cfg.Collectors.ProcessAccessEnabled {
		procAccess := collectors.NewProcessAccessCollector(eventChan, logger)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("ProcessAccess collector panicked and was safely recovered: %v", r)
				}
			}()
			if err := procAccess.Start(ctx); err != nil {
				logger.Warnf("ProcessAccess collector failed to start: %v", err)
			} else {
				logger.Info("ProcessAccess collector started")
			}
		}()
	} else {
		logger.Debug("ProcessAccess collector disabled by config")
	}

	// Vulnerability scanner collector (Trivy/Grype) — periodic local scans that
	// emit normalized vulnerability_finding telemetry events.
	if !cfg.Collectors.DisablePowerShellLogging {
		ps := collectors.NewPowerShellCollector(eventChan, logger, `C:\ProgramData\EDR\state`, true)
		a.RegisterDropSource("powershell", ps.Dropped)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("PowerShell collector panicked and was safely recovered: %v", r)
				}
			}()
			if err := ps.Start(ctx); err != nil {
				logger.Warnf("PowerShell collector failed to start: %v", err)
			} else {
				logger.Info("PowerShell script-block collector started (ps_script / ps_module telemetry)")
			}
		}()
	} else {
		logger.Info("PowerShell logging collector disabled by config")
	}

	if cfg.Collectors.VulnScanEnabled {
		vs := collectors.NewVulnerabilityScannerCollector(cfg.Collectors, eventChan, logger)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Vulnerability scanner collector panicked and was safely recovered: %v", r)
				}
			}()
			vs.Start(ctx)
		}()
		logger.Infof("Vulnerability scanner collector enabled (scanner=%s interval=%v)", cfg.Collectors.VulnScannerType, cfg.Collectors.VulnScanInterval)
	} else {
		logger.Debug("Vulnerability scanner collector disabled by config")
	}

	// NOTE: File monitoring and Image Load detection are now handled by
	// the ETW collector above (EVENT_TRACE_FLAG_FILE_IO_INIT and
	// EVENT_TRACE_FLAG_IMAGE_LOAD). They fire real-time from the kernel
	// with exact PID attribution — no separate polling collectors needed.
}
