package inspect

const Version = "0.2.0"

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Finding struct {
	RuleID      string `json:"ruleId"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	Target      string `json:"target"`
	State       string `json:"state,omitempty"`
}

type CheckError struct {
	Target  string `json:"target"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type DNSResult struct {
	Status  string   `json:"status"`
	Records []string `json:"records"`
	Error   string   `json:"error,omitempty"`
}

type DNSObservation struct {
	A     DNSResult `json:"a"`
	AAAA  DNSResult `json:"aaaa"`
	SPF   DNSResult `json:"spf"`
	DMARC DNSResult `json:"dmarc"`
	MX    DNSResult `json:"mx"`
}

type HTTPObservation struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
}

type TLSObservation struct {
	Authorized bool   `json:"authorized"`
	Protocol   string `json:"protocol"`
	ValidTo    string `json:"validTo"`
}

type Observation struct {
	URL        string           `json:"url"`
	Hostname   string           `json:"hostname"`
	Address    string           `json:"address,omitempty"`
	Addresses  []string         `json:"addresses"`
	ObservedAt string           `json:"observedAt"`
	HTTP       *HTTPObservation `json:"http,omitempty"`
	TLS        *TLSObservation  `json:"tls,omitempty"`
	DNS        *DNSObservation  `json:"dns,omitempty"`
}

type Report struct {
	SchemaVersion int            `json:"schemaVersion"`
	Tool          Tool           `json:"tool"`
	Kind          string         `json:"kind"`
	GeneratedAt   string         `json:"generatedAt"`
	Complete      bool           `json:"complete"`
	Targets       []string       `json:"targets"`
	Findings      []Finding      `json:"findings"`
	Errors        []CheckError   `json:"errors"`
	Observations  []Observation  `json:"observations"`
	Context       map[string]any `json:"context"`
}
