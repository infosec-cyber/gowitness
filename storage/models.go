package storage

import (
	"encoding/json"
	"strconv"
	"time"

	"gorm.io/gorm"
)

type Event struct {
	gorm.Model `json:"-"`

	Type     string `json:"type"`
	Name     string `json:"name"`
	Function string `json:"function"`
}

// URL contains information about a URL
type URL struct {
	gorm.Model `json:"-"`

	URL            string `json:"url"`
	FinalURL       string `json:"final_url"`
	ResponseCode   int    `json:"response_code"`
	ResponseReason string `json:"response_reason"`
	Proto          string `json:"proto"`
	ContentLength  int64  `json:"content_length"`
	Title          string `json:"title"`
	Filename       string `json:"-"`
	IsPDF          bool   `json:"-"`
	PerceptionHash string `json:"-"`
	DOM            string `json:"dom"`
	Screenshot     string `json:"-"`

	TLS TLS `json:"tls"`

	Headers       []Header      `json:"headers"`
	Technologies  []Technologie `json:"technologies"`
	Console       []ConsoleLog  `json:"console"`
	Network       []NetworkLog  `json:"network"`
	Events        []Event       `json:"events" gorm:"-"`
	ScreenshotUrl string        `json:"screenshot_url" gorm:"-"`
}

// AddHeader adds a new header to a URL
func (url *URL) AddHeader(key string, value string) {
	url.Headers = append(url.Headers, Header{
		Key:   key,
		Value: value,
	})
}

// AddTechnlogies adds a new technologies to a URL
func (url *URL) AddTechnologie(value string) {
	url.Technologies = append(url.Technologies, Technologie{
		Value: value,
	})
}

// MarshallCSV returns values as a slice
func (url *URL) MarshallCSV() (res []string) {
	return []string{url.URL,
		url.FinalURL,
		strconv.Itoa(url.ResponseCode),
		url.ResponseReason,
		url.Proto,
		strconv.Itoa(int(url.ContentLength)),
		url.Title,
		url.Filename}
}

// MarshallJSON returns values as a slice
func (url *URL) MarshallJSON() ([]byte, error) {
	var tmp struct {
		URL            string `json:"url"`
		FinalURL       string `json:"final_url"`
		ResponseCode   int    `json:"response_code"`
		ResponseReason string `json:"response_reason"`
		Proto          string `json:"proto"`
		ContentLength  int64  `json:"content_length"`
		Title          string `json:"title"`
		Filename       string `json:"file_name"`
	}

	tmp.URL = url.URL
	tmp.FinalURL = url.FinalURL
	tmp.ResponseCode = url.ResponseCode
	tmp.ResponseReason = url.ResponseReason
	tmp.Proto = url.Proto
	tmp.ContentLength = url.ContentLength
	tmp.Title = url.Title
	tmp.Filename = url.Filename

	return json.Marshal(&tmp)
}

// Header contains an HTTP header
type Header struct {
	gorm.Model `json:"-"`

	URLID uint `json:"-"`

	Key   string `json:"key"`
	Value string `json:"value"`
}

// Technologie contains a technologie
type Technologie struct {
	gorm.Model `json:"-"`

	URLID uint `json:"-"`

	Value string `json:"value"`
}

// TLS contains TLS information for a URL
type TLS struct {
	gorm.Model `json:"-"`

	URLID uint `json:"-"`

	Version         uint16           `json:"version"`
	ServerName      string           `json:"server_name"`
	TLSCertificates []TLSCertificate `json:"certificates"`
}

// TLSCertificate contain TLS Certificate information
type TLSCertificate struct {
	gorm.Model `json:"-"`

	TLSID uint `json:"-"`

	Raw                []byte                  `json:"-"`
	DNSNames           []TLSCertificateDNSName `json:"dns_names"`
	SubjectCommonName  string                  `json:"subject_common_name"`
	IssuerCommonName   string                  `json:"issuer_common_name"`
	SignatureAlgorithm string                  `json:"signature_algorithm"`
	PubkeyAlgorithm    string                  `json:"pubkey_algorithm"`
}

// AddDNSName adds a new DNS Name to a Certificate
func (tlsCert *TLSCertificate) AddDNSName(name string) {
	tlsCert.DNSNames = append(tlsCert.DNSNames, TLSCertificateDNSName{Name: name})
}

// TLSCertificateDNSName has DNS names for a TLS certificate
type TLSCertificateDNSName struct {
	gorm.Model `json:"-"`

	TLSCertificateID uint   `json:"-"`
	Name             string `json:"name"`
}

// ConsoleLog contains the console log, and exceptions emitted
type ConsoleLog struct {
	gorm.Model `json:"-"`

	URLID uint `json:"-"`

	Time  time.Time `json:"time"`
	Type  string    `json:"type"`
	Value string    `json:"value"`
}

// RequestType are network log types
type RequestType int

const (
	HTTP RequestType = 0
	WS
)

// NetworkLog contains Chrome networks events that were emitted
type NetworkLog struct {
	gorm.Model `json:"-"`

	URLID uint `json:"-"`

	RequestID   string      `json:"request_id"`
	RequestType RequestType `json:"request_type"`
	StatusCode  int64       `json:"status_code"`
	URL         string      `json:"url"`
	FinalURL    string      `json:"final_url"`
	IP          string      `json:"ip"`
	Time        time.Time   `json:"time"`
	Error       string      `json:"error"`
}
