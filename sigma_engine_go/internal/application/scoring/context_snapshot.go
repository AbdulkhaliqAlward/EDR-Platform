package scoring

import "time"

// ContextSnapshot is the forensic evidence record captured at the exact moment
// of risk scoring. It is JSON-serialized and stored in the `context_snapshot`
// JSONB column of the `alerts` table (added in Sprint 3).
//
// Design goals:
//   - Self-contained forensic reconstruction: a SOC analyst reading this record
//     can reconstruct exactly why a specific risk_score was assigned.
//   - Score transparency: ScoreBreakdown makes the formula auditable.
//   - Minimal storage: fields are omitted when zero/empty.
type ContextSnapshot struct {
	// Metadata
	ScoredAt time.Time `json:"scored_at"` // UTC timestamp of scoring

	// ── Process Image ────────────────────────────────────────────────────────
	ProcessName    string `json:"process_name,omitempty"`
	ProcessPath    string `json:"process_path,omitempty"`
	ProcessCmdLine string `json:"process_cmd_line,omitempty"` // max 512 chars

	// ── Privilege Context ────────────────────────────────────────────────────
	UserSID         string `json:"user_sid,omitempty"`
	UserName        string `json:"user_name,omitempty"`
	IntegrityLevel  string `json:"integrity_level,omitempty"` // "Low","Medium","High","System"
	IsElevated      bool   `json:"is_elevated"`
	SignatureStatus string `json:"signature_status,omitempty"` // "microsoft","trusted","unsigned"

	// ── Process Lineage ──────────────────────────────────────────────────────
	ParentPID       int64  `json:"parent_pid,omitempty"`
	ParentName      string `json:"parent_name,omitempty"`
	ParentPath      string `json:"parent_path,omitempty"`
	GrandparentName string `json:"grandparent_name,omitempty"`
	GrandparentPath string `json:"grandparent_path,omitempty"`

	// LineageSuspicion is the human-readable suspicion level from the matrix.
	// One of: "critical", "high", "medium", "low", "none"
	LineageSuspicion string `json:"lineage_suspicion"`

	// AncestorChain is the full reconstructed process tree from the lineage cache.
	// Index 0 = target process, index N = oldest ancestor found.
	AncestorChain []AncestorEntry `json:"ancestor_chain,omitempty"`

	// ── Temporal Burst ───────────────────────────────────────────────────────
	BurstCount     int `json:"burst_count"`      // rule category hits in window
	BurstWindowSec int `json:"burst_window_sec"` // window size (always 300)

	// ── Rule Metadata ────────────────────────────────────────────────────────
	RuleID       string   `json:"rule_id,omitempty"`
	RuleTitle    string   `json:"rule_title,omitempty"`
	RuleSeverity string   `json:"rule_severity,omitempty"`
	RuleCategory string   `json:"rule_category,omitempty"`
	MatchCount   int      `json:"match_count"`
	RelatedRules []string `json:"related_rules,omitempty"`

	// ── Score Transparency ───────────────────────────────────────────────────
	// ScoreBreakdown shows exactly how the final risk_score was computed.
	// Essential for academic justification and SOC analyst trust.
	ScoreBreakdown ScoreBreakdown `json:"score_breakdown"`

	// ── Context-Aware Policy Factors (Hybrid model) ──────────────────────────
	UserRoleWeight          float64  `json:"user_role_weight,omitempty"`
	DeviceCriticalityWeight float64  `json:"device_criticality_weight,omitempty"`
	NetworkAnomalyFactor    float64  `json:"network_anomaly_factor,omitempty"`
	ContextMultiplier       float64  `json:"context_multiplier,omitempty"`
	ContextQualityScore     float64  `json:"context_quality_score,omitempty"`
	QualityFactor           float64  `json:"quality_factor,omitempty"`
	MissingContextFields    []string `json:"missing_context_fields,omitempty"`

	// Warnings contains non-fatal scoring errors (e.g., lineage cache miss).
	// Presence of warnings indicates the score was computed with partial context.
	Warnings []string `json:"warnings,omitempty"`
}

// AncestorEntry represents a single node in the reconstructed process tree,
// serialised into ContextSnapshot.AncestorChain.
type AncestorEntry struct {
	PID        int64  `json:"pid"`
	Name       string `json:"name"`
	Path       string `json:"path,omitempty"`
	UserSID    string `json:"user_sid,omitempty"`
	Integrity  string `json:"integrity,omitempty"`
	IsElevated bool   `json:"is_elevated"`
	SigStatus  string `json:"sig_status,omitempty"`
	SeenAt     int64  `json:"seen_at"` // Unix seconds
}

// ScoreBreakdown is the component-level breakdown of the risk_score formula.
// Enables forensic transparency and academic justification.
//
// risk_score = clamp(BaseScore + LineageBonus + PrivilegeBonus + BurstBonus
//   - UEBABonus + InteractionBonus - FPDiscount - UEBADiscount, 0, 100)
type ScoreBreakdown struct {
	BaseScore               int     `json:"base_score"`            // from Sigma severity + multi-match
	LineageBonus            int     `json:"lineage_bonus"`         // from suspicious parent-child pair
	PrivilegeBonus          int     `json:"privilege_bonus"`       // from SYSTEM/elevated/unsigned
	BurstBonus              int     `json:"burst_bonus"`           // from temporal repeat firing
	FPDiscount              int     `json:"fp_discount"`           // subtracted for trusted signature
	UEBABonus               int     `json:"ueba_bonus"`            // +15 when process is anomalous
	UEBADiscount            int     `json:"ueba_discount"`         // +10 subtracted when process is normal
	UEBASignal              string  `json:"ueba_signal"`           // "anomaly", "normal", or "none"
	UEBAReason              string  `json:"ueba_reason,omitempty"` // why the UEBA signal was given
	InteractionBonus        int     `json:"interaction_bonus"`     // +10/+15 when multiple high signals co-occur
	UserRoleWeight          float64 `json:"user_role_weight,omitempty"`
	DeviceCriticalityWeight float64 `json:"device_criticality_weight,omitempty"`
	NetworkAnomalyFactor    float64 `json:"network_anomaly_factor,omitempty"`
	ContextMultiplier       float64 `json:"context_multiplier,omitempty"`
	ContextQualityScore     float64 `json:"context_quality_score,omitempty"`
	QualityFactor           float64 `json:"quality_factor,omitempty"`
	ContextAdjustedScore    int     `json:"context_adjusted_score,omitempty"` // after multiplier, before clamp
	RawScore                int     `json:"raw_score"`                        // before clamp
	FinalScore              int     `json:"final_score"`                      // after clamp(0,100)
}
