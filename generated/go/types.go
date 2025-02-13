// This file was auto-generated by Fern from our API Definition.

package methodwebtest

import (
	json "encoding/json"
	fmt "fmt"
	core "github.com/Method-Security/methodwebtest/generated/go/core"
	time "time"
)

type HeaderBufferOverflowConfig struct {
	Targets  []string `json:"targets,omitempty" url:"targets,omitempty"`
	BodySize int      `json:"bodySize" url:"bodySize"`
	Timeout  int      `json:"timeout" url:"timeout"`
	Retries  int      `json:"retries" url:"retries"`
	Sleep    int      `json:"sleep" url:"sleep"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (h *HeaderBufferOverflowConfig) GetExtraProperties() map[string]interface{} {
	return h.extraProperties
}

func (h *HeaderBufferOverflowConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler HeaderBufferOverflowConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*h = HeaderBufferOverflowConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *h)
	if err != nil {
		return err
	}
	h.extraProperties = extraProperties

	h._rawJSON = json.RawMessage(data)
	return nil
}

func (h *HeaderBufferOverflowConfig) String() string {
	if len(h._rawJSON) > 0 {
		if value, err := core.StringifyJSON(h._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(h); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", h)
}

type HeaderMisconfigurationConfig struct {
	Targets     []string    `json:"targets,omitempty" url:"targets,omitempty"`
	HeaderEvent HeaderEvent `json:"headerEvent" url:"headerEvent"`
	Timeout     int         `json:"timeout" url:"timeout"`
	Retries     int         `json:"retries" url:"retries"`
	Sleep       int         `json:"sleep" url:"sleep"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (h *HeaderMisconfigurationConfig) GetExtraProperties() map[string]interface{} {
	return h.extraProperties
}

func (h *HeaderMisconfigurationConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler HeaderMisconfigurationConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*h = HeaderMisconfigurationConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *h)
	if err != nil {
		return err
	}
	h.extraProperties = extraProperties

	h._rawJSON = json.RawMessage(data)
	return nil
}

func (h *HeaderMisconfigurationConfig) String() string {
	if len(h._rawJSON) > 0 {
		if value, err := core.StringifyJSON(h._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(h); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", h)
}

type HeaderServerOverloadConfig struct {
	Targets     []string `json:"targets,omitempty" url:"targets,omitempty"`
	HeaderNames []string `json:"headerNames,omitempty" url:"headerNames,omitempty"`
	PayloadSize int      `json:"payloadSize" url:"payloadSize"`
	Timeout     int      `json:"timeout" url:"timeout"`
	Retries     int      `json:"retries" url:"retries"`
	Sleep       int      `json:"sleep" url:"sleep"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (h *HeaderServerOverloadConfig) GetExtraProperties() map[string]interface{} {
	return h.extraProperties
}

func (h *HeaderServerOverloadConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler HeaderServerOverloadConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*h = HeaderServerOverloadConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *h)
	if err != nil {
		return err
	}
	h.extraProperties = extraProperties

	h._rawJSON = json.RawMessage(data)
	return nil
}

func (h *HeaderServerOverloadConfig) String() string {
	if len(h._rawJSON) > 0 {
		if value, err := core.StringifyJSON(h._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(h); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", h)
}

type HeaderUserAgentConfig struct {
	Targets     []string `json:"targets,omitempty" url:"targets,omitempty"`
	AgentHeader string   `json:"agentHeader" url:"agentHeader"`
	Timeout     int      `json:"timeout" url:"timeout"`
	Retries     int      `json:"retries" url:"retries"`
	Sleep       int      `json:"sleep" url:"sleep"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (h *HeaderUserAgentConfig) GetExtraProperties() map[string]interface{} {
	return h.extraProperties
}

func (h *HeaderUserAgentConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler HeaderUserAgentConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*h = HeaderUserAgentConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *h)
	if err != nil {
		return err
	}
	h.extraProperties = extraProperties

	h._rawJSON = json.RawMessage(data)
	return nil
}

func (h *HeaderUserAgentConfig) String() string {
	if len(h._rawJSON) > 0 {
		if value, err := core.StringifyJSON(h._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(h); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", h)
}

type InjectionLocation string

const (
	InjectionLocationHeader    InjectionLocation = "HEADER"
	InjectionLocationPath      InjectionLocation = "PATH"
	InjectionLocationQuery     InjectionLocation = "QUERY"
	InjectionLocationBody      InjectionLocation = "BODY"
	InjectionLocationForm      InjectionLocation = "FORM"
	InjectionLocationMultipart InjectionLocation = "MULTIPART"
)

func NewInjectionLocationFromString(s string) (InjectionLocation, error) {
	switch s {
	case "HEADER":
		return InjectionLocationHeader, nil
	case "PATH":
		return InjectionLocationPath, nil
	case "QUERY":
		return InjectionLocationQuery, nil
	case "BODY":
		return InjectionLocationBody, nil
	case "FORM":
		return InjectionLocationForm, nil
	case "MULTIPART":
		return InjectionLocationMultipart, nil
	}
	var t InjectionLocation
	return "", fmt.Errorf("%s is not a valid %T", s, t)
}

func (i InjectionLocation) Ptr() *InjectionLocation {
	return &i
}

type MultiInjectionConfig struct {
	Targets           []string          `json:"targets,omitempty" url:"targets,omitempty"`
	Method            HttpMethod        `json:"method" url:"method"`
	VariableData      map[string]string `json:"variableData,omitempty" url:"variableData,omitempty"`
	InjectionLocation InjectionLocation `json:"injectionLocation" url:"injectionLocation"`
	EventType         MultiEvent        `json:"eventType" url:"eventType"`
	Timeout           int               `json:"timeout" url:"timeout"`
	Retries           int               `json:"retries" url:"retries"`
	Sleep             int               `json:"sleep" url:"sleep"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (m *MultiInjectionConfig) GetExtraProperties() map[string]interface{} {
	return m.extraProperties
}

func (m *MultiInjectionConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler MultiInjectionConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*m = MultiInjectionConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *m)
	if err != nil {
		return err
	}
	m.extraProperties = extraProperties

	m._rawJSON = json.RawMessage(data)
	return nil
}

func (m *MultiInjectionConfig) String() string {
	if len(m._rawJSON) > 0 {
		if value, err := core.StringifyJSON(m._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(m); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", m)
}

type PathCrlfConfig struct {
	Targets     []string `json:"targets,omitempty" url:"targets,omitempty"`
	HeaderName  string   `json:"headerName" url:"headerName"`
	HeaderValue string   `json:"headerValue" url:"headerValue"`
	Timeout     int      `json:"timeout" url:"timeout"`
	Retries     int      `json:"retries" url:"retries"`
	Sleep       int      `json:"sleep" url:"sleep"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (p *PathCrlfConfig) GetExtraProperties() map[string]interface{} {
	return p.extraProperties
}

func (p *PathCrlfConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler PathCrlfConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*p = PathCrlfConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *p)
	if err != nil {
		return err
	}
	p.extraProperties = extraProperties

	p._rawJSON = json.RawMessage(data)
	return nil
}

func (p *PathCrlfConfig) String() string {
	if len(p._rawJSON) > 0 {
		if value, err := core.StringifyJSON(p._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(p); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", p)
}

type PathModFileConfig struct {
	Targets []string `json:"targets,omitempty" url:"targets,omitempty"`
	Timeout int      `json:"timeout" url:"timeout"`
	Retries int      `json:"retries" url:"retries"`
	Sleep   int      `json:"sleep" url:"sleep"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (p *PathModFileConfig) GetExtraProperties() map[string]interface{} {
	return p.extraProperties
}

func (p *PathModFileConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler PathModFileConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*p = PathModFileConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *p)
	if err != nil {
		return err
	}
	p.extraProperties = extraProperties

	p._rawJSON = json.RawMessage(data)
	return nil
}

func (p *PathModFileConfig) String() string {
	if len(p._rawJSON) > 0 {
		if value, err := core.StringifyJSON(p._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(p); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", p)
}

type PathTraversalConfig struct {
	Targets           []string `json:"targets,omitempty" url:"targets,omitempty"`
	Paths             []string `json:"paths,omitempty" url:"paths,omitempty"`
	PathLists         []string `json:"pathLists,omitempty" url:"pathLists,omitempty"`
	QueryParam        *string  `json:"queryParam,omitempty" url:"queryParam,omitempty"`
	ResponseCodes     string   `json:"responseCodes" url:"responseCodes"`
	IgnoreBaseContent bool     `json:"ignoreBaseContent" url:"ignoreBaseContent"`
	Timeout           int      `json:"timeout" url:"timeout"`
	Retries           int      `json:"retries" url:"retries"`
	Sleep             int      `json:"sleep" url:"sleep"`
	SuccessfulOnly    bool     `json:"successfulOnly" url:"successfulOnly"`
	Threshold         float64  `json:"threshold" url:"threshold"`
	MaxRunTime        *int     `json:"maxRunTime,omitempty" url:"maxRunTime,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (p *PathTraversalConfig) GetExtraProperties() map[string]interface{} {
	return p.extraProperties
}

func (p *PathTraversalConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler PathTraversalConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*p = PathTraversalConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *p)
	if err != nil {
		return err
	}
	p.extraProperties = extraProperties

	p._rawJSON = json.RawMessage(data)
	return nil
}

func (p *PathTraversalConfig) String() string {
	if len(p._rawJSON) > 0 {
		if value, err := core.StringifyJSON(p._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(p); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", p)
}

type QueryReverseProxyConfig struct {
	Targets         []string `json:"targets,omitempty" url:"targets,omitempty"`
	RedirectAddress string   `json:"redirectAddress" url:"redirectAddress"`
	Timeout         int      `json:"timeout" url:"timeout"`
	Retries         int      `json:"retries" url:"retries"`
	Sleep           int      `json:"sleep" url:"sleep"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (q *QueryReverseProxyConfig) GetExtraProperties() map[string]interface{} {
	return q.extraProperties
}

func (q *QueryReverseProxyConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler QueryReverseProxyConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*q = QueryReverseProxyConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *q)
	if err != nil {
		return err
	}
	q.extraProperties = extraProperties

	q._rawJSON = json.RawMessage(data)
	return nil
}

func (q *QueryReverseProxyConfig) String() string {
	if len(q._rawJSON) > 0 {
		if value, err := core.StringifyJSON(q._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(q); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", q)
}

type AttemptInfo struct {
	Request      *RequestInfo `json:"request,omitempty" url:"request,omitempty"`
	TimeSent     time.Time    `json:"timeSent" url:"timeSent"`
	TimeReceived *time.Time   `json:"timeReceived,omitempty" url:"timeReceived,omitempty"`
	Finding      *bool        `json:"finding,omitempty" url:"finding,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (a *AttemptInfo) GetExtraProperties() map[string]interface{} {
	return a.extraProperties
}

func (a *AttemptInfo) UnmarshalJSON(data []byte) error {
	type embed AttemptInfo
	var unmarshaler = struct {
		embed
		TimeSent     *core.DateTime `json:"timeSent"`
		TimeReceived *core.DateTime `json:"timeReceived,omitempty"`
	}{
		embed: embed(*a),
	}
	if err := json.Unmarshal(data, &unmarshaler); err != nil {
		return err
	}
	*a = AttemptInfo(unmarshaler.embed)
	a.TimeSent = unmarshaler.TimeSent.Time()
	a.TimeReceived = unmarshaler.TimeReceived.TimePtr()

	extraProperties, err := core.ExtractExtraProperties(data, *a)
	if err != nil {
		return err
	}
	a.extraProperties = extraProperties

	a._rawJSON = json.RawMessage(data)
	return nil
}

func (a *AttemptInfo) MarshalJSON() ([]byte, error) {
	type embed AttemptInfo
	var marshaler = struct {
		embed
		TimeSent     *core.DateTime `json:"timeSent"`
		TimeReceived *core.DateTime `json:"timeReceived,omitempty"`
	}{
		embed:        embed(*a),
		TimeSent:     core.NewDateTime(a.TimeSent),
		TimeReceived: core.NewOptionalDateTime(a.TimeReceived),
	}
	return json.Marshal(marshaler)
}

func (a *AttemptInfo) String() string {
	if len(a._rawJSON) > 0 {
		if value, err := core.StringifyJSON(a._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(a); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", a)
}

type EngineConfig struct {
	Type                               string
	InjectionEngineConfig              *InjectionEngineConfig
	HeaderMisconfigurationEngineConfig *HeaderMisconfigurationEngineConfig
	PathTraversalEngineConfig          *PathTraversalEngineConfig
}

func NewEngineConfigFromInjectionEngineConfig(value *InjectionEngineConfig) *EngineConfig {
	return &EngineConfig{Type: "InjectionEngineConfig", InjectionEngineConfig: value}
}

func NewEngineConfigFromHeaderMisconfigurationEngineConfig(value *HeaderMisconfigurationEngineConfig) *EngineConfig {
	return &EngineConfig{Type: "HeaderMisconfigurationEngineConfig", HeaderMisconfigurationEngineConfig: value}
}

func NewEngineConfigFromPathTraversalEngineConfig(value *PathTraversalEngineConfig) *EngineConfig {
	return &EngineConfig{Type: "PathTraversalEngineConfig", PathTraversalEngineConfig: value}
}

func (e *EngineConfig) UnmarshalJSON(data []byte) error {
	var unmarshaler struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &unmarshaler); err != nil {
		return err
	}
	e.Type = unmarshaler.Type
	if unmarshaler.Type == "" {
		return fmt.Errorf("%T did not include discriminant type", e)
	}
	switch unmarshaler.Type {
	case "InjectionEngineConfig":
		value := new(InjectionEngineConfig)
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		e.InjectionEngineConfig = value
	case "HeaderMisconfigurationEngineConfig":
		value := new(HeaderMisconfigurationEngineConfig)
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		e.HeaderMisconfigurationEngineConfig = value
	case "PathTraversalEngineConfig":
		value := new(PathTraversalEngineConfig)
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		e.PathTraversalEngineConfig = value
	}
	return nil
}

func (e EngineConfig) MarshalJSON() ([]byte, error) {
	switch e.Type {
	default:
		return nil, fmt.Errorf("invalid type %s in %T", e.Type, e)
	case "InjectionEngineConfig":
		return core.MarshalJSONWithExtraProperty(e.InjectionEngineConfig, "type", "InjectionEngineConfig")
	case "HeaderMisconfigurationEngineConfig":
		return core.MarshalJSONWithExtraProperty(e.HeaderMisconfigurationEngineConfig, "type", "HeaderMisconfigurationEngineConfig")
	case "PathTraversalEngineConfig":
		return core.MarshalJSONWithExtraProperty(e.PathTraversalEngineConfig, "type", "PathTraversalEngineConfig")
	}
}

type EngineConfigVisitor interface {
	VisitInjectionEngineConfig(*InjectionEngineConfig) error
	VisitHeaderMisconfigurationEngineConfig(*HeaderMisconfigurationEngineConfig) error
	VisitPathTraversalEngineConfig(*PathTraversalEngineConfig) error
}

func (e *EngineConfig) Accept(visitor EngineConfigVisitor) error {
	switch e.Type {
	default:
		return fmt.Errorf("invalid type %s in %T", e.Type, e)
	case "InjectionEngineConfig":
		return visitor.VisitInjectionEngineConfig(e.InjectionEngineConfig)
	case "HeaderMisconfigurationEngineConfig":
		return visitor.VisitHeaderMisconfigurationEngineConfig(e.HeaderMisconfigurationEngineConfig)
	case "PathTraversalEngineConfig":
		return visitor.VisitPathTraversalEngineConfig(e.PathTraversalEngineConfig)
	}
}

type HeaderMisconfigurationEngineConfig struct {
	Targets   []string              `json:"targets,omitempty" url:"targets,omitempty"`
	Method    HttpMethod            `json:"method" url:"method"`
	Payloads  [][]map[string]string `json:"payloads,omitempty" url:"payloads,omitempty"`
	EventType *EventType            `json:"eventType,omitempty" url:"eventType,omitempty"`
	Timeout   int                   `json:"timeout" url:"timeout"`
	Retries   int                   `json:"retries" url:"retries"`
	Sleep     int                   `json:"sleep" url:"sleep"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (h *HeaderMisconfigurationEngineConfig) GetExtraProperties() map[string]interface{} {
	return h.extraProperties
}

func (h *HeaderMisconfigurationEngineConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler HeaderMisconfigurationEngineConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*h = HeaderMisconfigurationEngineConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *h)
	if err != nil {
		return err
	}
	h.extraProperties = extraProperties

	h._rawJSON = json.RawMessage(data)
	return nil
}

func (h *HeaderMisconfigurationEngineConfig) String() string {
	if len(h._rawJSON) > 0 {
		if value, err := core.StringifyJSON(h._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(h); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", h)
}

type InjectionEngineConfig struct {
	Targets           []string            `json:"targets,omitempty" url:"targets,omitempty"`
	Method            HttpMethod          `json:"method" url:"method"`
	Paths             []string            `json:"paths,omitempty" url:"paths,omitempty"`
	BaselinePayload   map[string]string   `json:"baselinePayload,omitempty" url:"baselinePayload,omitempty"`
	InjectedPayloads  []map[string]string `json:"injectedPayloads,omitempty" url:"injectedPayloads,omitempty"`
	InjectionLocation InjectionLocation   `json:"injectionLocation" url:"injectionLocation"`
	EventType         *EventType          `json:"eventType,omitempty" url:"eventType,omitempty"`
	Timeout           int                 `json:"timeout" url:"timeout"`
	Retries           int                 `json:"retries" url:"retries"`
	Sleep             int                 `json:"sleep" url:"sleep"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (i *InjectionEngineConfig) GetExtraProperties() map[string]interface{} {
	return i.extraProperties
}

func (i *InjectionEngineConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler InjectionEngineConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*i = InjectionEngineConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *i)
	if err != nil {
		return err
	}
	i.extraProperties = extraProperties

	i._rawJSON = json.RawMessage(data)
	return nil
}

func (i *InjectionEngineConfig) String() string {
	if len(i._rawJSON) > 0 {
		if value, err := core.StringifyJSON(i._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(i); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", i)
}

type PathTraversalEngineConfig struct {
	Targets           []string `json:"targets,omitempty" url:"targets,omitempty"`
	Paths             []string `json:"paths,omitempty" url:"paths,omitempty"`
	PathFiles         []string `json:"pathFiles,omitempty" url:"pathFiles,omitempty"`
	QueryParam        *string  `json:"queryParam,omitempty" url:"queryParam,omitempty"`
	ResponseCodes     string   `json:"responseCodes" url:"responseCodes"`
	IgnoreBaseContent bool     `json:"ignoreBaseContent" url:"ignoreBaseContent"`
	Timeout           int      `json:"timeout" url:"timeout"`
	Retries           int      `json:"retries" url:"retries"`
	Sleep             int      `json:"sleep" url:"sleep"`
	SuccessfulOnly    bool     `json:"successfulOnly" url:"successfulOnly"`
	Threshold         *float64 `json:"threshold,omitempty" url:"threshold,omitempty"`
	MaxRunTime        *int     `json:"maxRunTime,omitempty" url:"maxRunTime,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (p *PathTraversalEngineConfig) GetExtraProperties() map[string]interface{} {
	return p.extraProperties
}

func (p *PathTraversalEngineConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler PathTraversalEngineConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*p = PathTraversalEngineConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *p)
	if err != nil {
		return err
	}
	p.extraProperties = extraProperties

	p._rawJSON = json.RawMessage(data)
	return nil
}

func (p *PathTraversalEngineConfig) String() string {
	if len(p._rawJSON) > 0 {
		if value, err := core.StringifyJSON(p._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(p); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", p)
}

type Report struct {
	Targets []*TargetInfo `json:"targets,omitempty" url:"targets,omitempty"`
	Config  *EngineConfig `json:"config,omitempty" url:"config,omitempty"`
	Errors  []string      `json:"errors,omitempty" url:"errors,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (r *Report) GetExtraProperties() map[string]interface{} {
	return r.extraProperties
}

func (r *Report) UnmarshalJSON(data []byte) error {
	type unmarshaler Report
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*r = Report(value)

	extraProperties, err := core.ExtractExtraProperties(data, *r)
	if err != nil {
		return err
	}
	r.extraProperties = extraProperties

	r._rawJSON = json.RawMessage(data)
	return nil
}

func (r *Report) String() string {
	if len(r._rawJSON) > 0 {
		if value, err := core.StringifyJSON(r._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(r); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", r)
}

type TargetInfo struct {
	Target          string         `json:"target" url:"target"`
	StartTimestamp  time.Time      `json:"startTimestamp" url:"startTimestamp"`
	EndTimestamp    time.Time      `json:"endTimestamp" url:"endTimestamp"`
	RequestCount    int            `json:"requestCount" url:"requestCount"`
	BaselineAttempt *AttemptInfo   `json:"baselineAttempt,omitempty" url:"baselineAttempt,omitempty"`
	Attempts        []*AttemptInfo `json:"attempts,omitempty" url:"attempts,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (t *TargetInfo) GetExtraProperties() map[string]interface{} {
	return t.extraProperties
}

func (t *TargetInfo) UnmarshalJSON(data []byte) error {
	type embed TargetInfo
	var unmarshaler = struct {
		embed
		StartTimestamp *core.DateTime `json:"startTimestamp"`
		EndTimestamp   *core.DateTime `json:"endTimestamp"`
	}{
		embed: embed(*t),
	}
	if err := json.Unmarshal(data, &unmarshaler); err != nil {
		return err
	}
	*t = TargetInfo(unmarshaler.embed)
	t.StartTimestamp = unmarshaler.StartTimestamp.Time()
	t.EndTimestamp = unmarshaler.EndTimestamp.Time()

	extraProperties, err := core.ExtractExtraProperties(data, *t)
	if err != nil {
		return err
	}
	t.extraProperties = extraProperties

	t._rawJSON = json.RawMessage(data)
	return nil
}

func (t *TargetInfo) MarshalJSON() ([]byte, error) {
	type embed TargetInfo
	var marshaler = struct {
		embed
		StartTimestamp *core.DateTime `json:"startTimestamp"`
		EndTimestamp   *core.DateTime `json:"endTimestamp"`
	}{
		embed:          embed(*t),
		StartTimestamp: core.NewDateTime(t.StartTimestamp),
		EndTimestamp:   core.NewDateTime(t.EndTimestamp),
	}
	return json.Marshal(marshaler)
}

func (t *TargetInfo) String() string {
	if len(t._rawJSON) > 0 {
		if value, err := core.StringifyJSON(t._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(t); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", t)
}

type EventType struct {
	Type        string
	HeaderEvent HeaderEvent
	PathEvent   PathEvent
	QueryEvent  QueryEvent
	MultiEvent  MultiEvent
}

func NewEventTypeFromHeaderEvent(value HeaderEvent) *EventType {
	return &EventType{Type: "HeaderEvent", HeaderEvent: value}
}

func NewEventTypeFromPathEvent(value PathEvent) *EventType {
	return &EventType{Type: "PathEvent", PathEvent: value}
}

func NewEventTypeFromQueryEvent(value QueryEvent) *EventType {
	return &EventType{Type: "QueryEvent", QueryEvent: value}
}

func NewEventTypeFromMultiEvent(value MultiEvent) *EventType {
	return &EventType{Type: "MultiEvent", MultiEvent: value}
}

func (e *EventType) UnmarshalJSON(data []byte) error {
	var unmarshaler struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &unmarshaler); err != nil {
		return err
	}
	e.Type = unmarshaler.Type
	if unmarshaler.Type == "" {
		return fmt.Errorf("%T did not include discriminant type", e)
	}
	switch unmarshaler.Type {
	case "HeaderEvent":
		var valueUnmarshaler struct {
			HeaderEvent HeaderEvent `json:"value"`
		}
		if err := json.Unmarshal(data, &valueUnmarshaler); err != nil {
			return err
		}
		e.HeaderEvent = valueUnmarshaler.HeaderEvent
	case "PathEvent":
		var valueUnmarshaler struct {
			PathEvent PathEvent `json:"value"`
		}
		if err := json.Unmarshal(data, &valueUnmarshaler); err != nil {
			return err
		}
		e.PathEvent = valueUnmarshaler.PathEvent
	case "QueryEvent":
		var valueUnmarshaler struct {
			QueryEvent QueryEvent `json:"value"`
		}
		if err := json.Unmarshal(data, &valueUnmarshaler); err != nil {
			return err
		}
		e.QueryEvent = valueUnmarshaler.QueryEvent
	case "MultiEvent":
		var valueUnmarshaler struct {
			MultiEvent MultiEvent `json:"value"`
		}
		if err := json.Unmarshal(data, &valueUnmarshaler); err != nil {
			return err
		}
		e.MultiEvent = valueUnmarshaler.MultiEvent
	}
	return nil
}

func (e EventType) MarshalJSON() ([]byte, error) {
	switch e.Type {
	default:
		return nil, fmt.Errorf("invalid type %s in %T", e.Type, e)
	case "HeaderEvent":
		var marshaler = struct {
			Type        string      `json:"type"`
			HeaderEvent HeaderEvent `json:"value"`
		}{
			Type:        "HeaderEvent",
			HeaderEvent: e.HeaderEvent,
		}
		return json.Marshal(marshaler)
	case "PathEvent":
		var marshaler = struct {
			Type      string    `json:"type"`
			PathEvent PathEvent `json:"value"`
		}{
			Type:      "PathEvent",
			PathEvent: e.PathEvent,
		}
		return json.Marshal(marshaler)
	case "QueryEvent":
		var marshaler = struct {
			Type       string     `json:"type"`
			QueryEvent QueryEvent `json:"value"`
		}{
			Type:       "QueryEvent",
			QueryEvent: e.QueryEvent,
		}
		return json.Marshal(marshaler)
	case "MultiEvent":
		var marshaler = struct {
			Type       string     `json:"type"`
			MultiEvent MultiEvent `json:"value"`
		}{
			Type:       "MultiEvent",
			MultiEvent: e.MultiEvent,
		}
		return json.Marshal(marshaler)
	}
}

type EventTypeVisitor interface {
	VisitHeaderEvent(HeaderEvent) error
	VisitPathEvent(PathEvent) error
	VisitQueryEvent(QueryEvent) error
	VisitMultiEvent(MultiEvent) error
}

func (e *EventType) Accept(visitor EventTypeVisitor) error {
	switch e.Type {
	default:
		return fmt.Errorf("invalid type %s in %T", e.Type, e)
	case "HeaderEvent":
		return visitor.VisitHeaderEvent(e.HeaderEvent)
	case "PathEvent":
		return visitor.VisitPathEvent(e.PathEvent)
	case "QueryEvent":
		return visitor.VisitQueryEvent(e.QueryEvent)
	case "MultiEvent":
		return visitor.VisitMultiEvent(e.MultiEvent)
	}
}

type HeaderEvent string

const (
	HeaderEventCors             HeaderEvent = "CORS"
	HeaderEventEscape           HeaderEvent = "ESCAPE"
	HeaderEventHttp             HeaderEvent = "HTTP"
	HeaderEventSensitiveexposed HeaderEvent = "SENSITIVEEXPOSED"
	HeaderEventServeroverload   HeaderEvent = "SERVEROVERLOAD"
	HeaderEventUseragent        HeaderEvent = "USERAGENT"
)

func NewHeaderEventFromString(s string) (HeaderEvent, error) {
	switch s {
	case "CORS":
		return HeaderEventCors, nil
	case "ESCAPE":
		return HeaderEventEscape, nil
	case "HTTP":
		return HeaderEventHttp, nil
	case "SENSITIVEEXPOSED":
		return HeaderEventSensitiveexposed, nil
	case "SERVEROVERLOAD":
		return HeaderEventServeroverload, nil
	case "USERAGENT":
		return HeaderEventUseragent, nil
	}
	var t HeaderEvent
	return "", fmt.Errorf("%s is not a valid %T", s, t)
}

func (h HeaderEvent) Ptr() *HeaderEvent {
	return &h
}

type HttpMethod string

const (
	HttpMethodGet     HttpMethod = "GET"
	HttpMethodPost    HttpMethod = "POST"
	HttpMethodPut     HttpMethod = "PUT"
	HttpMethodDelete  HttpMethod = "DELETE"
	HttpMethodPatch   HttpMethod = "PATCH"
	HttpMethodOptions HttpMethod = "OPTIONS"
	HttpMethodHead    HttpMethod = "HEAD"
	HttpMethodConnect HttpMethod = "CONNECT"
	HttpMethodTrace   HttpMethod = "TRACE"
)

func NewHttpMethodFromString(s string) (HttpMethod, error) {
	switch s {
	case "GET":
		return HttpMethodGet, nil
	case "POST":
		return HttpMethodPost, nil
	case "PUT":
		return HttpMethodPut, nil
	case "DELETE":
		return HttpMethodDelete, nil
	case "PATCH":
		return HttpMethodPatch, nil
	case "OPTIONS":
		return HttpMethodOptions, nil
	case "HEAD":
		return HttpMethodHead, nil
	case "CONNECT":
		return HttpMethodConnect, nil
	case "TRACE":
		return HttpMethodTrace, nil
	}
	var t HttpMethod
	return "", fmt.Errorf("%s is not a valid %T", s, t)
}

func (h HttpMethod) Ptr() *HttpMethod {
	return &h
}

type MultiEvent string

const (
	MultiEventCommandecho      MultiEvent = "COMMANDECHO"
	MultiEventCommandtimedelay MultiEvent = "COMMANDTIMEDELAY"
	MultiEventSqliboolean      MultiEvent = "SQLIBOOLEAN"
	MultiEventSqliescape       MultiEvent = "SQLIESCAPE"
	MultiEventSqlitimedelay    MultiEvent = "SQLITIMEDELAY"
	MultiEventXssalert         MultiEvent = "XSSALERT"
)

func NewMultiEventFromString(s string) (MultiEvent, error) {
	switch s {
	case "COMMANDECHO":
		return MultiEventCommandecho, nil
	case "COMMANDTIMEDELAY":
		return MultiEventCommandtimedelay, nil
	case "SQLIBOOLEAN":
		return MultiEventSqliboolean, nil
	case "SQLIESCAPE":
		return MultiEventSqliescape, nil
	case "SQLITIMEDELAY":
		return MultiEventSqlitimedelay, nil
	case "XSSALERT":
		return MultiEventXssalert, nil
	}
	var t MultiEvent
	return "", fmt.Errorf("%s is not a valid %T", s, t)
}

func (m MultiEvent) Ptr() *MultiEvent {
	return &m
}

type PathEvent string

const (
	PathEventTraversal PathEvent = "TRAVERSAL"
	PathEventCrlf      PathEvent = "CRLF"
)

func NewPathEventFromString(s string) (PathEvent, error) {
	switch s {
	case "TRAVERSAL":
		return PathEventTraversal, nil
	case "CRLF":
		return PathEventCrlf, nil
	}
	var t PathEvent
	return "", fmt.Errorf("%s is not a valid %T", s, t)
}

func (p PathEvent) Ptr() *PathEvent {
	return &p
}

type QueryEvent string

const (
	QueryEventRedirect QueryEvent = "REDIRECT"
)

func NewQueryEventFromString(s string) (QueryEvent, error) {
	switch s {
	case "REDIRECT":
		return QueryEventRedirect, nil
	}
	var t QueryEvent
	return "", fmt.Errorf("%s is not a valid %T", s, t)
}

func (q QueryEvent) Ptr() *QueryEvent {
	return &q
}

type RequestInfo struct {
	BaseUrl             string            `json:"baseUrl" url:"baseUrl"`
	Path                string            `json:"path" url:"path"`
	Method              HttpMethod        `json:"method" url:"method"`
	PathParams          map[string]string `json:"pathParams,omitempty" url:"pathParams,omitempty"`
	QueryParams         map[string]string `json:"queryParams,omitempty" url:"queryParams,omitempty"`
	HeaderParams        map[string]string `json:"headerParams,omitempty" url:"headerParams,omitempty"`
	BodyParams          *string           `json:"bodyParams,omitempty" url:"bodyParams,omitempty"`
	FormParams          map[string]string `json:"formParams,omitempty" url:"formParams,omitempty"`
	MultipartParams     map[string]string `json:"multipartParams,omitempty" url:"multipartParams,omitempty"`
	EventType           []*EventType      `json:"eventType,omitempty" url:"eventType,omitempty"`
	StatusCode          *int              `json:"statusCode,omitempty" url:"statusCode,omitempty"`
	ResponseBody        *string           `json:"responseBody,omitempty" url:"responseBody,omitempty"`
	ResponseBodyEncoded *string           `json:"responseBodyEncoded,omitempty" url:"responseBodyEncoded,omitempty"`
	ResponseHeaders     map[string]string `json:"responseHeaders,omitempty" url:"responseHeaders,omitempty"`
	Errors              []string          `json:"errors,omitempty" url:"errors,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (r *RequestInfo) GetExtraProperties() map[string]interface{} {
	return r.extraProperties
}

func (r *RequestInfo) UnmarshalJSON(data []byte) error {
	type unmarshaler RequestInfo
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*r = RequestInfo(value)

	extraProperties, err := core.ExtractExtraProperties(data, *r)
	if err != nil {
		return err
	}
	r.extraProperties = extraProperties

	r._rawJSON = json.RawMessage(data)
	return nil
}

func (r *RequestInfo) String() string {
	if len(r._rawJSON) > 0 {
		if value, err := core.StringifyJSON(r._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(r); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", r)
}

type RequestParams struct {
	PathParams      map[string]string `json:"pathParams,omitempty" url:"pathParams,omitempty"`
	QueryParams     map[string]string `json:"queryParams,omitempty" url:"queryParams,omitempty"`
	HeaderParams    map[string]string `json:"headerParams,omitempty" url:"headerParams,omitempty"`
	BodyParams      string            `json:"bodyParams" url:"bodyParams"`
	FormParams      map[string]string `json:"formParams,omitempty" url:"formParams,omitempty"`
	MultipartParams map[string]string `json:"multipartParams,omitempty" url:"multipartParams,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (r *RequestParams) GetExtraProperties() map[string]interface{} {
	return r.extraProperties
}

func (r *RequestParams) UnmarshalJSON(data []byte) error {
	type unmarshaler RequestParams
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*r = RequestParams(value)

	extraProperties, err := core.ExtractExtraProperties(data, *r)
	if err != nil {
		return err
	}
	r.extraProperties = extraProperties

	r._rawJSON = json.RawMessage(data)
	return nil
}

func (r *RequestParams) String() string {
	if len(r._rawJSON) > 0 {
		if value, err := core.StringifyJSON(r._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(r); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", r)
}
