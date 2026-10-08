package rules

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"gopkg.in/yaml.v3"
)

const (
	DefaultBufferSize  = 64 * 1024        // 64KB
	DefaultMaxRuleSize = 10 * 1024 * 1024 // 10MB
	DefaultMaxWorkers  = 0                // 0 = runtime.NumCPU()
)

// ParsingError represents an error encountered during rule parsing with context.
type ParsingError struct {
	Path    string
	Err     error
	Line    int
	Col     int
	Context string
}

func (pe ParsingError) Error() string {
	if pe.Line > 0 {
		return fmt.Sprintf("%s:%d:%d: %v", pe.Path, pe.Line, pe.Col, pe.Err)
	}
	return fmt.Sprintf("%s: %v", pe.Path, pe.Err)
}

// ErrorCallback is called for each parsing error.
type ErrorCallback func(ParsingError)

// ProgressFunc is called to report loading progress.
type ProgressFunc func(loaded int, errors int, total int)

// ParallelLoaderConfig configures parallel rule loading.
type ParallelLoaderConfig struct {
	MaxWorkers       int
	BufferSize       int
	MaxRuleSize      int64
	ErrorHandler     ErrorCallback
	ProgressCallback ProgressFunc
}

// DefaultConfig returns default parallel loader configuration.
func DefaultConfig() ParallelLoaderConfig {
	// Rule parsing is typically I/O bound (reading many small YAML files),
	// so we default to more workers than CPU count. Cap to avoid oversubscription.
	// Increased from 4x to ensure better parallelism for I/O-bound tasks.
	maxWorkers := runtime.NumCPU() * 4
	if maxWorkers < 4 {
		maxWorkers = 4
	}
	if maxWorkers > 32 {
		maxWorkers = 32
	}

	return ParallelLoaderConfig{
		MaxWorkers:       maxWorkers,
		BufferSize:       DefaultBufferSize,
		MaxRuleSize:      DefaultMaxRuleSize,
		ErrorHandler:     nil,
		ProgressCallback: nil,
	}
}

// RuleParser parses Sigma YAML rules with validation and parallel loading support.
type RuleParser struct {
	strict           bool
	productWhitelist map[string]bool // Products to load (empty = all)
}

// NewRuleParser creates a new rule parser.
func NewRuleParser(strict bool) *RuleParser {
	return &RuleParser{
		strict:           strict,
		productWhitelist: make(map[string]bool),
	}
}

// SetProductWhitelist sets the product whitelist for rule filtering.
// If whitelist is empty, all products are allowed.
func (p *RuleParser) SetProductWhitelist(products []string) {
	p.productWhitelist = make(map[string]bool)
	for _, product := range products {
		p.productWhitelist[strings.ToLower(product)] = true
	}
}

// ParseFile parses a single YAML rule file with buffered I/O.
func (p *RuleParser) ParseFile(path string) (*domain.SigmaRule, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open rule file %s: %w", path, err)
	}
	defer file.Close()

	// Get file size for validation
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat file %s: %w", path, err)
	}

	if fileInfo.Size() > DefaultMaxRuleSize {
		return nil, fmt.Errorf("file %s exceeds maximum size (%d bytes)", path, DefaultMaxRuleSize)
	}

	return p.parseReader(file)
}

// ParseContent uses the same parser and size limit as disk loading.
func (p *RuleParser) ParseContent(content string) (*domain.SigmaRule, error) {
	if len(content) > DefaultMaxRuleSize {
		return nil, fmt.Errorf("rule exceeds maximum size (%d bytes)", DefaultMaxRuleSize)
	}
	return p.parseReader(strings.NewReader(content))
}

func (p *RuleParser) parseReader(input io.Reader) (*domain.SigmaRule, error) {
	reader := bufio.NewReaderSize(input, DefaultBufferSize)

	// Parse YAML
	var yamlRule yamlRule
	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&yamlRule); err != nil {
		return nil, fmt.Errorf("yaml parsing failed: %w", err)
	}

	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("rule content must contain one YAML document")
	}

	// Validate
	if err := yamlRule.validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Convert to domain model
	rule, err := yamlRule.toSigmaRule()
	if err != nil {
		return nil, fmt.Errorf("conversion failed: %w", err)
	}

	// Product whitelist filtering (skip silently if product not in whitelist)
	if len(p.productWhitelist) > 0 && rule.LogSource.Product != nil {
		productLower := strings.ToLower(*rule.LogSource.Product)
		if !p.productWhitelist[productLower] {
			// Product not in whitelist - skip this rule silently
			// Return a special error that loader will treat as skip, not error
			return nil, fmt.Errorf("SKIP: product %s not in whitelist", *rule.LogSource.Product)
		}
	}

	// Final validation
	if err := rule.Validate(); err != nil {
		return nil, fmt.Errorf("rule validation failed: %w", err)
	}

	return rule, nil
}

// ParseDirectoryParallel loads rules from a directory using parallel workers and streaming.
// Returns channels for rules and errors, allowing streaming consumption.
func (p *RuleParser) ParseDirectoryParallel(
	ctx context.Context,
	dirPath string,
	config ParallelLoaderConfig,
) (<-chan *domain.SigmaRule, <-chan ParsingError, error) {
	// Validate directory
	info, err := os.Stat(dirPath)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid directory %s: %w", dirPath, err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", dirPath)
	}

	// Setup channels
	ruleChan := make(chan *domain.SigmaRule, 100)
	errorChan := make(chan ParsingError, 100)
	jobs := make(chan string, 1000)

	// Determine worker count
	maxWorkers := config.MaxWorkers
	if maxWorkers == 0 {
		// Use DefaultConfig logic for better parallelism (I/O bound)
		maxWorkers = runtime.NumCPU() * 4
		if maxWorkers < 4 {
			maxWorkers = 4
		}
		if maxWorkers > 32 {
			maxWorkers = 32
		}
	}

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go p.worker(ctx, jobs, ruleChan, errorChan, &wg)
	}

	// Start file scanner
	var scanWg sync.WaitGroup
	scanWg.Add(1)
	go func() {
		defer scanWg.Done()
		p.scanFiles(ctx, dirPath, jobs)
		close(jobs)
	}()

	// Close channels when done
	go func() {
		wg.Wait()
		close(ruleChan)
		close(errorChan)
	}()

	return ruleChan, errorChan, nil
}

// worker processes rule files from the jobs channel.
func (p *RuleParser) worker(
	ctx context.Context,
	jobs <-chan string,
	results chan<- *domain.SigmaRule,
	errors chan<- ParsingError,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for path := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			rule, err := p.ParseFile(path)
			if err != nil {
				errors <- ParsingError{
					Path: path,
					Err:  err,
				}
				continue
			}

			select {
			case results <- rule:
			case <-ctx.Done():
				return
			}
		}
	}
}

// scanFiles recursively scans directory for YAML files and sends them to jobs channel.
func (p *RuleParser) scanFiles(ctx context.Context, dirPath string, jobs chan<- string) {
	err := filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Continue on error
		}

		if d.IsDir() {
			return nil
		}

		// Check if YAML file
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		select {
		case jobs <- path:
		case <-ctx.Done():
			return ctx.Err()
		}

		return nil
	})

	if err != nil && err != context.Canceled {
		logger.Warnf("Error scanning directory: %v", err)
	}
}

// ParseDirectoryBatch loads all rules from a directory and returns them as a slice.
// Uses parallel loading internally but aggregates results.
func (p *RuleParser) ParseDirectoryBatch(
	ctx context.Context,
	dirPath string,
	config ParallelLoaderConfig,
) ([]*domain.SigmaRule, []ParsingError, error) {
	ruleChan, errorChan, err := p.ParseDirectoryParallel(ctx, dirPath, config)
	if err != nil {
		return nil, nil, err
	}

	var rules []*domain.SigmaRule
	var errors []ParsingError

	// Track progress
	var loadedCount int64
	var errorCount int64

	// Collect results
	done := false
	for !done {
		select {
		case rule, ok := <-ruleChan:
			if !ok {
				ruleChan = nil
			} else {
				rules = append(rules, rule)
				atomic.AddInt64(&loadedCount, 1)
				if config.ProgressCallback != nil {
					config.ProgressCallback(int(loadedCount), int(errorCount), 0)
				}
			}

		case err, ok := <-errorChan:
			if !ok {
				errorChan = nil
			} else {
				errors = append(errors, err)
				atomic.AddInt64(&errorCount, 1)
				if config.ErrorHandler != nil {
					config.ErrorHandler(err)
				}
				if config.ProgressCallback != nil {
					config.ProgressCallback(int(loadedCount), int(errorCount), 0)
				}
			}

		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}

		if ruleChan == nil && errorChan == nil {
			done = true
		}
	}

	return rules, errors, nil
}

// yamlRule represents the raw YAML structure of a Sigma rule.
type yamlRule struct {
	Title          string                 `yaml:"title"`
	ID             string                 `yaml:"id"`
	Status         string                 `yaml:"status,omitempty"`
	Description    string                 `yaml:"description,omitempty"`
	LogSource      yamlLogSource          `yaml:"logsource,omitempty"`
	Detection      map[string]interface{} `yaml:"detection"`
	Level          string                 `yaml:"level,omitempty"`
	Tags           []string               `yaml:"tags,omitempty"`
	FalsePositives []string               `yaml:"falsepositives,omitempty"`
	Author         string                 `yaml:"author,omitempty"`
	Date           string                 `yaml:"date,omitempty"`
	Modified       string                 `yaml:"modified,omitempty"`
	References     []string               `yaml:"references,omitempty"`
}

// yamlLogSource represents the logsource section in YAML.
type yamlLogSource struct {
	Product  *string `yaml:"product,omitempty"`
	Category *string `yaml:"category,omitempty"`
	Service  *string `yaml:"service,omitempty"`
}

// validate validates the YAML rule structure.
func (yr *yamlRule) validate() error {
	if yr.Title == "" {
		return fmt.Errorf("title is required")
	}
	if len(yr.Title) < 5 {
		return fmt.Errorf("title must be at least 5 characters")
	}

	if yr.Detection == nil {
		return fmt.Errorf("detection section is required")
	}

	if _, ok := yr.Detection["condition"]; !ok {
		return fmt.Errorf("detection.condition is required")
	}

	// Check for at least one selection
	hasSelection := false
	for key := range yr.Detection {
		if key != "condition" && key != "timeframe" {
			hasSelection = true
			break
		}
	}
	if !hasSelection {
		return fmt.Errorf("detection must have at least one selection")
	}

	// Validate level
	if yr.Level != "" {
		validLevels := map[string]bool{
			"informational": true,
			"low":           true,
			"medium":        true,
			"high":          true,
			"critical":      true,
		}
		if !validLevels[strings.ToLower(yr.Level)] {
			return fmt.Errorf("invalid level: %s", yr.Level)
		}
	}

	// Validate status
	if yr.Status != "" {
		validStatuses := map[string]bool{
			"stable":       true,
			"test":         true,
			"experimental": true,
			"deprecated":   true,
			"unsupported":  true,
		}
		if !validStatuses[strings.ToLower(yr.Status)] {
			return fmt.Errorf("invalid status: %s", yr.Status)
		}
	}

	return nil
}

// toSigmaRule converts yamlRule to domain.SigmaRule.
func (yr *yamlRule) toSigmaRule() (*domain.SigmaRule, error) {
	// Parse logsource
	logSource := domain.LogSource{
		Product:  yr.LogSource.Product,
		Category: yr.LogSource.Category,
		Service:  yr.LogSource.Service,
	}

	// Parse detection
	detection, err := parseDetection(yr.Detection)
	if err != nil {
		return nil, fmt.Errorf("failed to parse detection: %w", err)
	}

	// Generate ID if missing
	id := yr.ID
	if id == "" {
		id = generateRuleID(yr.Title)
	}

	// Set defaults
	level := yr.Level
	if level == "" {
		level = "medium"
	}

	status := yr.Status
	if status == "" {
		status = "test"
	}

	return &domain.SigmaRule{
		ID:             id,
		Title:          yr.Title,
		Status:         status,
		Description:    yr.Description,
		LogSource:      logSource,
		Detection:      *detection,
		Level:          level,
		Tags:           yr.Tags,
		FalsePositives: yr.FalsePositives,
		Author:         yr.Author,
		Date:           yr.Date,
		Modified:       yr.Modified,
		References:     yr.References,
	}, nil
}

// parseDetection parses the detection section from YAML.
func parseDetection(detectionData map[string]interface{}) (*domain.Detection, error) {
	detection := &domain.Detection{
		Selections: make(map[string]*domain.Selection),
	}

	// Extract condition. Sigma allows a list of conditions, which are
	// alternatives (logical OR).
	switch cond := detectionData["condition"].(type) {
	case string:
		detection.Condition = cond
	case []interface{}:
		parts := make([]string, 0, len(cond))
		for _, c := range cond {
			s, ok := c.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return nil, fmt.Errorf("detection.condition list must contain non-empty strings")
			}
			parts = append(parts, "("+s+")")
		}
		if len(parts) == 0 {
			return nil, fmt.Errorf("detection.condition list is empty")
		}
		detection.Condition = strings.Join(parts, " or ")
	default:
		return nil, fmt.Errorf("detection.condition must be a string or a list of strings")
	}

	// Extract timeframe
	if tf, ok := detectionData["timeframe"].(string); ok {
		detection.Timeframe = &tf
	}

	// Parse selections
	for key, value := range detectionData {
		if key == "condition" || key == "timeframe" {
			continue
		}

		selection, err := parseSelection(key, value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse selection %s: %w", key, err)
		}

		detection.Selections[key] = selection
	}

	return detection, nil
}

// parseSelection parses a selection from YAML.
func parseSelection(name string, data interface{}) (*domain.Selection, error) {
	selection := &domain.Selection{
		Name:   name,
		Fields: make([]domain.SelectionField, 0),
	}

	// A list is either keywords (list of scalars → full-text search) or
	// alternatives (list of maps → OR of field selections). Mixing the two
	// is not valid Sigma and is rejected instead of silently dropping items.
	if items, ok := data.([]interface{}); ok {
		if len(items) == 0 {
			return nil, fmt.Errorf("selection list is empty")
		}
		if _, isMap := items[0].(map[string]interface{}); isMap {
			selection.Alternatives = make([]domain.Selection, 0, len(items))
			for i, item := range items {
				m, ok := item.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("selection list item %d is %T; a list of maps cannot mix other values", i, item)
				}
				alt, err := parseSelection(fmt.Sprintf("%s[%d]", name, i), m)
				if err != nil {
					return nil, err
				}
				selection.Alternatives = append(selection.Alternatives, *alt)
			}
			return selection, nil
		}

		selection.IsKeywordSelection = true
		selection.Keywords = make([]string, 0, len(items))
		for i, kw := range items {
			switch v := kw.(type) {
			case string:
				selection.Keywords = append(selection.Keywords, v)
			case int, int64, float64, bool:
				selection.Keywords = append(selection.Keywords, domain.ValueToString(v))
			default:
				return nil, fmt.Errorf("keyword list item %d is %T; keywords must be scalar values", i, kw)
			}
		}
		return selection, nil
	}

	// Handle field-based selection (map)
	if fields, ok := data.(map[string]interface{}); ok {
		for fieldSpec, values := range fields {
			field, err := parseSelectionField(fieldSpec, values)
			if err != nil {
				return nil, fmt.Errorf("failed to parse field %s: %w", fieldSpec, err)
			}
			selection.Fields = append(selection.Fields, *field)
		}
		return selection, nil
	}

	return nil, fmt.Errorf("selection must be a list or map")
}

// parseSelectionField parses a selection field with modifiers.
// Pre-compiles regex patterns for performance optimization.
func parseSelectionField(fieldSpec string, values interface{}) (*domain.SelectionField, error) {
	// Parse field name and modifiers (e.g., "CommandLine|contains|all")
	parts := strings.Split(fieldSpec, "|")
	fieldName := parts[0]
	modifiers := parts[1:]

	// Normalize values to list
	var valueList []interface{}
	switch v := values.(type) {
	case []interface{}:
		valueList = v
	case interface{}:
		valueList = []interface{}{v}
	default:
		valueList = []interface{}{values}
	}

	field := &domain.SelectionField{
		FieldName: fieldName,
		Values:    valueList,
		Modifiers: modifiers,
		IsNegated: false,
	}

	// Pre-compile regex patterns if "regex" or "re" modifier is present
	hasRegexModifier := false
	for _, mod := range modifiers {
		if strings.EqualFold(mod, "regex") || strings.EqualFold(mod, "re") {
			hasRegexModifier = true
			break
		}
	}

	if hasRegexModifier {
		// Compile all regex patterns during rule loading
		compiledRegex := make([]*regexp.Regexp, 0, len(valueList))
		for _, val := range valueList {
			patternStr := fmt.Sprintf("%v", val)
			re, err := regexp.Compile(patternStr)
			if err != nil {
				// Log warning but don't fail rule loading - invalid regex will fail at match time
				logger.Warnf("Failed to compile regex pattern %q: %v", patternStr, err)
				continue
			}
			compiledRegex = append(compiledRegex, re)
		}
		field.CompiledRegex = compiledRegex
	}

	return field, nil
}

// generateRuleID generates a deterministic ID from title.
func generateRuleID(title string) string {
	// Simple hash-based ID (in production, use proper UUID)
	hash := 0
	for _, char := range title {
		hash = hash*31 + int(char)
	}
	return fmt.Sprintf("rule-%x", hash)
}
