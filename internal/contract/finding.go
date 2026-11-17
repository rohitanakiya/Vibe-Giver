// Package contract binds Vibe Giver to Vibe Killer's findings contract.
//
// Giver is a consumer. Everything in this package exists so that the two
// cannot drift apart quietly: the schema is vendored from a pinned published
// artifact, the Go model is checked against it field by field in both
// directions, and an envelope this build does not understand is refused
// rather than read optimistically.
//
// The reason that refusal is loud, and asymmetric, is the whole point of the
// tool. Giver's output is the claim "this vulnerability is gone". If a future
// Killer adds another way of saying "this layer did not look" and Giver reads
// the document anyway, every finding suppressed that way becomes a finding
// Giver reports as fixed. The failure is silent, it points in the
// safe-looking direction, and it closes real holes as done.
package contract

// FindingSchemaVersion is the per-finding schema version this build speaks.
//
// It is pinned by "const": "1.0" in Killer's published schema, and it does
// not move: bumping it would invalidate every document ever written, to
// describe a change that did not touch a finding. Envelope changes move
// DocumentSchemaVersion instead.
const FindingSchemaVersion = "1.0"

// Severity ranks how bad a finding is if exploited.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityOrder = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Weight returns the comparable weight of a severity, and false if the value
// is not one this build knows.
func (s Severity) Weight() (int, bool) {
	w, ok := severityOrder[s]
	return w, ok
}

// AtLeast reports whether s is as severe as threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	sw, sok := severityOrder[s]
	tw, tok := severityOrder[threshold]
	if !sok || !tok {
		return false
	}
	return sw >= tw
}

// Confidence records how sure Killer is that a finding is real. Confirmed is
// reserved for findings reproduced by an actual non-destructive check.
type Confidence string

const (
	ConfidenceHeuristic Confidence = "heuristic"
	ConfidenceLikely    Confidence = "likely"
	ConfidenceConfirmed Confidence = "confirmed"
)

var confidenceOrder = map[Confidence]int{
	ConfidenceHeuristic: 0,
	ConfidenceLikely:    1,
	ConfidenceConfirmed: 2,
}

// Weight returns the comparable weight of a confidence level.
func (c Confidence) Weight() (int, bool) {
	w, ok := confidenceOrder[c]
	return w, ok
}

// Source names the engine that produced a finding.
type Source string

const (
	SourceSAST        Source = "sast"
	SourceDAST        Source = "dast"
	SourceRuntime     Source = "runtime"
	SourceDeps        Source = "deps"
	SourceSecrets     Source = "secrets"
	SourceBlastRadius Source = "blast-radius"
)

// AllSources is every source in the contract.
var AllSources = []Source{
	SourceSAST, SourceDAST, SourceRuntime, SourceDeps, SourceSecrets, SourceBlastRadius,
}

// Category is the OWASP-aligned bucket a finding belongs to.
type Category string

const (
	CategoryBrokenAccessControl Category = "broken-access-control"
	CategoryCryptoFailure       Category = "cryptographic-failure"
	CategoryInjection           Category = "injection"
	CategoryInsecureDesign      Category = "insecure-design"
	CategoryMisconfiguration    Category = "security-misconfiguration"
	CategoryVulnerableDep       Category = "vulnerable-dependency"
	CategoryAuthFailure         Category = "identification-and-authentication-failure"
	CategoryIntegrityFailure    Category = "software-and-data-integrity-failure"
	CategoryLoggingFailure      Category = "logging-and-monitoring-failure"
	CategorySSRF                Category = "server-side-request-forgery"
	CategorySecretsExposure     Category = "secrets-exposure"
	CategoryCrossService        Category = "cross-service-exposure"
)

// AllCategories is every category in the contract, in the schema order.
//
// There are twelve. The build brief said "roughly 25 contract categories",
// which conflated categories with rules: the published v1.0.0 rule pack holds
// 45 Semgrep rules and the binary registers 14 checks, and all of them land
// in these twelve buckets. Strategy selection keys off this list.
var AllCategories = []Category{
	CategoryBrokenAccessControl,
	CategoryCryptoFailure,
	CategoryInjection,
	CategoryInsecureDesign,
	CategoryMisconfiguration,
	CategoryVulnerableDep,
	CategoryAuthFailure,
	CategoryIntegrityFailure,
	CategoryLoggingFailure,
	CategorySSRF,
	CategorySecretsExposure,
	CategoryCrossService,
}

// Status tracks a finding across runs.
type Status string

const (
	StatusOpen          Status = "open"
	StatusFixed         Status = "fixed"
	StatusRegressed     Status = "regressed"
	StatusAccepted      Status = "accepted"
	StatusFalsePositive Status = "false_positive"
)

// LocationType says what kind of thing a finding points at.
type LocationType string

const (
	LocationCode       LocationType = "code"
	LocationEndpoint   LocationType = "endpoint"
	LocationDependency LocationType = "dependency"
	LocationConfig     LocationType = "config"
)

// Location points at the thing that is wrong.
type Location struct {
	Type      LocationType `json:"type"`
	File      string       `json:"file,omitempty"`
	Line      int          `json:"line,omitempty"`
	EndLine   int          `json:"end_line,omitempty"`
	Symbol    string       `json:"symbol,omitempty"`
	Endpoint  string       `json:"endpoint,omitempty"`
	Package   string       `json:"package,omitempty"`
	Ecosystem string       `json:"ecosystem,omitempty"`
	Version   string       `json:"version,omitempty"`
	ConfigKey string       `json:"config_key,omitempty"`

	// RepoRev is the tree Killer analyzed. The brief has Giver branch from
	// it. It is informational in Killer, deliberately excluded from
	// finding_id, so it can be empty or name a revision this checkout does
	// not have.
	RepoRev string `json:"repo_rev,omitempty"`
}

// TaintStep is one hop in a source-to-sink data-flow path.
type TaintStep struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Symbol string `json:"symbol,omitempty"`
	Note   string `json:"note"`
}

// Request records what a dynamic check sent. Auth holds a seeded-user label,
// never a token value, and Giver has to keep it that way when it quotes
// evidence into a pull request body.
type Request struct {
	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	Auth    string            `json:"auth,omitempty"`
}

// Evidence is why Killer believes the finding is real.
type Evidence struct {
	Summary     string      `json:"summary"`
	Request     *Request    `json:"request,omitempty"`
	Observed    string      `json:"observed,omitempty"`
	Expected    string      `json:"expected,omitempty"`
	Snippet     string      `json:"snippet,omitempty"`
	TaintPath   []TaintStep `json:"taint_path,omitempty"`
	EvidenceKey string      `json:"evidence_key,omitempty"`
}

// ReproKind is how a finding is re-verified.
type ReproKind string

const (
	ReproHTTP   ReproKind = "http"
	ReproScript ReproKind = "script"
	ReproStatic ReproKind = "static"
)

// Reproduction tells a human, or Giver, how to see the issue again.
//
// Its presence does not mean that `vibekiller reproduce` can re-run it. In
// the published v1.0.0 binary three endpoint checks emit Kind "http" with
// steps and implement no single-finding re-run at all. Reproducibility is a
// property of the check, not of this block; see RuleIsReproducible.
type Reproduction struct {
	Kind         ReproKind `json:"kind"`
	Command      string    `json:"command,omitempty"`
	Steps        []string  `json:"steps,omitempty"`
	ArtifactPath string    `json:"artifact_path,omitempty"`
}

// BlastRadius describes cross-service exposure, always scoped to the
// operator declared targets.
type BlastRadius struct {
	ReachableFrom string   `json:"reachable_from"`
	Reached       []string `json:"reached"`
	Scope         string   `json:"scope"`
}

// ScopeDeclaredOnly is the only legal BlastRadius scope.
const ScopeDeclaredOnly = "declared-targets-only"

// Remediation is Killer's handoff to whoever fixes the issue, and Giver's
// primary input for generating a fix.
type Remediation struct {
	Guidance       string   `json:"guidance"`
	RootCauseHint  string   `json:"root_cause_hint,omitempty"`
	References     []string `json:"references,omitempty"`
	FixableByGiver bool     `json:"fixable_by_giver"`

	// HumanRequiredReason is set whenever FixableByGiver is false. Killer
	// validates that, so Giver can rely on having something to print in the
	// human-action report rather than dropping the finding silently.
	HumanRequiredReason string `json:"human_required_reason,omitempty"`
}

// Finding is one security issue: the unit of the Killer-to-Giver contract.
type Finding struct {
	SchemaVersion string     `json:"schema_version"`
	FindingID     string     `json:"finding_id"`
	RuleID        string     `json:"rule_id"`
	Title         string     `json:"title"`
	Category      Category   `json:"category"`
	CWE           string     `json:"cwe,omitempty"`
	Severity      Severity   `json:"severity"`
	Confidence    Confidence `json:"confidence"`
	Source        Source     `json:"source"`

	Location     Location      `json:"location"`
	Evidence     Evidence      `json:"evidence"`
	Reproduction *Reproduction `json:"reproduction,omitempty"`
	BlastRadius  *BlastRadius  `json:"blast_radius,omitempty"`
	Remediation  Remediation   `json:"remediation"`

	Status Status `json:"status"`

	Rank       float64  `json:"rank,omitempty"`
	MergedFrom []Source `json:"merged_from,omitempty"`

	FirstSeenRun string `json:"first_seen_run,omitempty"`
	LastSeenRun  string `json:"last_seen_run,omitempty"`
}
