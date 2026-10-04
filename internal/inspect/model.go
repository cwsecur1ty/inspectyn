package inspect

const Version = "0.3.0-dev"

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
	A     DNSResult  `json:"a"`
	AAAA  DNSResult  `json:"aaaa"`
	SPF   DNSResult  `json:"spf"`
	DMARC DNSResult  `json:"dmarc"`
	MX    DNSResult  `json:"mx"`
	NS    *DNSResult `json:"ns,omitempty"`
	CNAME *DNSResult `json:"cname,omitempty"`
}

type HTTPObservation struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Cookies *CookieObservation  `json:"cookies,omitempty"`
}

type CookieObservation struct {
	Status  string             `json:"status"`
	Total   int                `json:"total"`
	Invalid int                `json:"invalid"`
	Items   []CookieAttributes `json:"items"`
}

type CookieAttributes struct {
	Index        int    `json:"index"`
	Name         string `json:"name"`
	Secure       bool   `json:"secure"`
	HTTPOnly     bool   `json:"httpOnly"`
	SameSite     string `json:"sameSite"`
	DomainScoped bool   `json:"domainScoped"`
	PathRoot     bool   `json:"pathRoot"`
	Partitioned  bool   `json:"partitioned"`
}

type TLSObservation struct {
	Authorized          bool     `json:"authorized"`
	Protocol            string   `json:"protocol"`
	ValidTo             string   `json:"validTo"`
	ValidFrom           string   `json:"validFrom,omitempty"`
	Subject             string   `json:"subject,omitempty"`
	Issuer              string   `json:"issuer,omitempty"`
	DNSNames            []string `json:"dnsNames,omitempty"`
	DNSNamesTruncated   bool     `json:"dnsNamesTruncated,omitempty"`
	FingerprintSHA256   string   `json:"fingerprintSha256,omitempty"`
	SerialNumber        string   `json:"serialNumber,omitempty"`
	SignatureAlgorithm  string   `json:"signatureAlgorithm,omitempty"`
	PublicKeyAlgorithm  string   `json:"publicKeyAlgorithm,omitempty"`
	PublicKeyBits       int      `json:"publicKeyBits,omitempty"`
	CipherSuite         string   `json:"cipherSuite,omitempty"`
	NegotiatedProtocol  string   `json:"negotiatedProtocol,omitempty"`
	VerifiedChainLength int      `json:"verifiedChainLength,omitempty"`
}

type SecurityTXTObservation struct {
	URL              string   `json:"url"`
	Status           string   `json:"status"`
	HTTPStatus       int      `json:"httpStatus,omitempty"`
	ContactCount     int      `json:"contactCount"`
	Expires          string   `json:"expires,omitempty"`
	CanonicalPresent bool     `json:"canonicalPresent"`
	CanonicalMatches bool     `json:"canonicalMatches"`
	Signed           bool     `json:"signed"`
	Issues           []string `json:"issues"`
}

type Observation struct {
	URL         string                  `json:"url"`
	Hostname    string                  `json:"hostname"`
	Address     string                  `json:"address,omitempty"`
	Addresses   []string                `json:"addresses"`
	ObservedAt  string                  `json:"observedAt"`
	HTTP        *HTTPObservation        `json:"http,omitempty"`
	TLS         *TLSObservation         `json:"tls,omitempty"`
	DNS         *DNSObservation         `json:"dns,omitempty"`
	SecurityTXT *SecurityTXTObservation `json:"securityTxt,omitempty"`
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
