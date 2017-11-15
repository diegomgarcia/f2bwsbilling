package f2bwsbilling

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"time"
)

// against "unused imports"
var _ time.Time
var _ xml.Name

type F2bCobranca struct {
	XMLName xml.Name `xml:"m:F2bCobranca"` //`xml:"http://www.f2b.com.br/soap/wsbilling.xsd F2bCobranca"`
	XmlNS   string   `xml:"xmlns:m,attr"`

	Mensagem Mensagem `xml:"mensagem,omitempty"`

	Sacador Sacador `xml:"sacador,omitempty"`

	Cobranca Cobranca `xml:"cobranca,omitempty"`

	Agendamento Agendamento `xml:"agendamento,omitempty"`

	Sacado []Sacado `xml:"sacado,omitempty"`
}

type Mensagem struct {
	Data string `xml:"data,attr,omitempty"`

	Numero string `xml:"numero,attr,omitempty"`

	Tipo_ws string `xml:"tipo_ws,attr,omitempty"`
}

type Sacador struct {
	Value string `xml:",chardata"`

	Conta string `xml:"conta,attr,omitempty"`
}
type Cobranca struct {
	Demonstrativo []string `xml:"demonstrativo,omitempty"`

	Sacador_avalista string `xml:"sacador_avalista,omitempty"`

	Desconto *Desconto `xml:"desconto,omitempty"`

	Multa *Multa `xml:"multa,omitempty"`

	Valor float64 `xml:"valor,attr,omitempty"`

	Tipo_cobranca string `xml:"tipo_cobranca,attr,omitempty"`

	Num_document int32 `xml:"num_document,attr,omitempty"`

	Cod_banco string `xml:"cod_banco,attr,omitempty"`

	Taxa float64 `xml:"taxa,attr,omitempty"`

	Tipo_taxa int32 `xml:"tipo_taxa,attr,omitempty"`

	Tipo_parcelamento string `xml:"tipo_parcelamento,attr,omitempty"`

	Num_parcelas int32 `xml:"num_parcelas,attr,omitempty"`
}

type Multa struct {
	Valor float64 `xml:"valor,attr,omitempty"`

	Tipo_multa int32 `xml:"tipo_multa,attr,omitempty"`

	Valor_dia float64 `xml:"valor_dia,attr,omitempty"`

	Tipo_multa_dia int32 `xml:"tipo_multa_dia,attr,omitempty"`

	Atraso int32 `xml:"atraso,attr,omitempty"`
}

type Desconto struct {
	Valor float64 `xml:"valor,attr,omitempty"`

	Tipo_desconto int32 `xml:"tipo_desconto,attr,omitempty"`

	Antecedencia int32 `xml:"antecedencia,attr,omitempty"`
}

type Agendamento struct {
	Value string `xml:",chardata"`

	Vencimento string `xml:"vencimento,attr,omitempty"`

	Ultimo_dia string `xml:"ultimo_dia,attr,omitempty"`

	Antecedencia int32 `xml:"antecedencia,attr,omitempty"`

	Periodicidade int32 `xml:"periodicidade,attr,omitempty"`

	Periodos int32 `xml:"periodos,attr,omitempty"`

	Sem_vencimento string `xml:"sem_vencimento,attr,omitempty"`

	Carne string `xml:"carne,attr,omitempty"`
}

type Sacado struct {
	Nome string `xml:"nome,omitempty"`

	Email string `xml:"email,omitempty"`

	Endereco *Endereco `xml:"endereco,omitempty"`

	Telefone *Telefone `xml:"telefone,omitempty"`

	Telefone_com *Telefone_com `xml:"telefone_com,omitempty"`

	Telefone_cel *Telefone_cel `xml:"telefone_cel,omitempty"`

	Cpf string `xml:"cpf,omitempty"`

	Cnpj string `xml:"cnpj,omitempty"`

	Observacao string `xml:"observacao,omitempty"`

	Grupo string `xml:"grupo,attr,omitempty"`

	Codigo string `xml:"codigo,attr,omitempty"`

	Envio string `xml:"envio,attr,omitempty"`

	Atualizar string `xml:"atualizar,attr,omitempty"`

	Servicos string `xml:"servicos,attr,omitempty"`
}

type Endereco struct {
	Logradouro string `xml:"logradouro,attr,omitempty"`

	Numero string `xml:"numero,attr,omitempty"`

	Complemento string `xml:"complemento,attr,omitempty"`

	Bairro string `xml:"bairro,attr,omitempty"`

	Cidade string `xml:"cidade,attr,omitempty"`

	Estado string `xml:"estado,attr,omitempty"`

	Cep string `xml:"cep,attr,omitempty"`
}

type Telefone struct {
	Ddd int32 `xml:"ddd,attr,omitempty"`

	Numero int32 `xml:"numero,attr,omitempty"`
}

type Telefone_com struct {
	Ddd_com int32 `xml:"ddd_com,attr,omitempty"`

	Numero_com int32 `xml:"numero_com,attr,omitempty"`
}

type Telefone_cel struct {
	Ddd_cel int32 `xml:"ddd_cel,attr,omitempty"`

	Numero_cel int32 `xml:"numero_cel,attr,omitempty"`
}

type F2bCobrancaRetorno struct {
	XMLName xml.Name `xml:"http://www.f2b.com.br/soap/wsbilling.xsd F2bCobrancaRetorno"`
	XmlNS   string   `xml:"xmlns:m,attr"`
	Sacado  []struct {
		Nome string `xml:"nome,omitempty"`

		Email string `xml:"email,omitempty"`

		Numero int32 `xml:"numero,attr,omitempty"`
	} `xml:"sacado,omitempty"`

	Agendamento struct {
		Value string

		Numero int32 `xml:"numero,attr,omitempty"`
	} `xml:"agendamento,omitempty"`

	Cobranca []struct {
		Nome string `xml:"nome,omitempty"`

		Email string `xml:"email,omitempty"`

		Url string `xml:"url,omitempty"`

		Numero int32 `xml:"numero,attr,omitempty"`

		Taxa_registro float64 `xml:"taxa_registro,attr,omitempty"`

		Nosso_numero int32 `xml:"nosso_numero,attr,omitempty"`
	} `xml:"cobranca,omitempty"`

	Carne []struct {
		Url string `xml:"url,omitempty"`

		Numero int32 `xml:"numero,attr,omitempty"`
	} `xml:"carne,omitempty"`

	Log string `xml:"log,omitempty"`
}

type WSBillingPortType struct {
	client *SOAPClient
}

func NewWSBillingPortType(url string, tls bool, auth *BasicAuth) *WSBillingPortType {
	if url == "" {
		url = ""
	}
	client := NewSOAPClient(url, tls, auth)

	return &WSBillingPortType{
		client: client,
	}
}

func NewWSBillingPortTypeWithTLSConfig(url string, tlsCfg *tls.Config, auth *BasicAuth) *WSBillingPortType {
	if url == "" {
		url = ""
	}
	client := NewSOAPClientWithTLSConfig(url, tlsCfg, auth)

	return &WSBillingPortType{
		client: client,
	}
}

func (service *WSBillingPortType) AddHeader(header interface{}) {
	service.client.AddHeader(header)
}

// Backwards-compatible function: use AddHeader instead
func (service *WSBillingPortType) SetHeader(header interface{}) {
	service.client.AddHeader(header)
}

func (service *WSBillingPortType) RegisterWSBilling(request *F2bCobranca) (*F2bCobrancaRetorno, error) {
	response := new(F2bCobrancaRetorno)
	response.XmlNS = "http://www.f2b.com.br/soap/wsbilling.xsd"

	err := service.client.Call("http://www.f2b.com.br/WSBilling", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

var timeout = time.Duration(30 * time.Second)

func dialTimeout(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

type SOAPEnvelope struct {
	XMLName xml.Name `xml:"soap-env:Envelope"`
	XmlNS   string   `xml:"xmlns:soap-env,attr"`
	Header  *SOAPHeader
	Body    SOAPBody
}

type SOAPHeader struct {
	XMLName xml.Name `xml:"soap-env:Header"`
	XmlNS   string   `xml:"xmlns:soap-env,attr"`

	Items []interface{} `xml:",omitempty"`
}

type SOAPBody struct {
	XMLName xml.Name `xml:"soap-env:Body"`

	Fault   *SOAPFault  `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

type SOAPFault struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`

	Code   string `xml:"faultcode,omitempty"`
	String string `xml:"faultstring,omitempty"`
	Actor  string `xml:"faultactor,omitempty"`
	Detail string `xml:"detail,omitempty"`
}

type ResponseSOAPEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Header  *SOAPHeader
	Body    ResponseSOAPBody
}
type ResponseSOAPHeader struct {
	XMLName xml.Name `xml:"Header"`

	Items []interface{} `xml:",omitempty"`
}

type ResponseSOAPBody struct {
	XMLName xml.Name `xml:"Body"`

	Fault   *SOAPFault  `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

const (
	// Predefined WSS namespaces to be used in
	WssNsWSSE string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	WssNsWSU  string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	WssNsType string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
)

type WSSSecurityHeader struct {
	XMLName   xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ wsse:Security"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`

	MustUnderstand string `xml:"mustUnderstand,attr,omitempty"`

	Token *WSSUsernameToken `xml:",omitempty"`
}

type WSSUsernameToken struct {
	XMLName   xml.Name `xml:"wsse:UsernameToken"`
	XmlNSWsu  string   `xml:"xmlns:wsu,attr"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`

	Id string `xml:"wsu:Id,attr,omitempty"`

	Username *WSSUsername `xml:",omitempty"`
	Password *WSSPassword `xml:",omitempty"`
}

type WSSUsername struct {
	XMLName   xml.Name `xml:"wsse:Username"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`

	Data string `xml:",chardata"`
}

type WSSPassword struct {
	XMLName   xml.Name `xml:"wsse:Password"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`
	XmlNSType string   `xml:"Type,attr"`

	Data string `xml:",chardata"`
}

type BasicAuth struct {
	Login    string
	Password string
}

type SOAPClient struct {
	url     string
	tlsCfg  *tls.Config
	auth    *BasicAuth
	headers []interface{}
}

// **********
// Accepted solution from http://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang
// Author: Icza - http://stackoverflow.com/users/1705598/icza

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func randStringBytesMaskImprSrc(n int) string {
	src := rand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}

// **********

func NewWSSSecurityHeader(user, pass, mustUnderstand string) *WSSSecurityHeader {
	hdr := &WSSSecurityHeader{XmlNSWsse: WssNsWSSE, MustUnderstand: mustUnderstand}
	hdr.Token = &WSSUsernameToken{XmlNSWsu: WssNsWSU, XmlNSWsse: WssNsWSSE, Id: "UsernameToken-" + randStringBytesMaskImprSrc(9)}
	hdr.Token.Username = &WSSUsername{XmlNSWsse: WssNsWSSE, Data: user}
	hdr.Token.Password = &WSSPassword{XmlNSWsse: WssNsWSSE, XmlNSType: WssNsType, Data: pass}
	return hdr
}

func (b *ResponseSOAPBody) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}

	var (
		token    xml.Token
		err      error
		consumed bool
	)

Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}

		if token == nil {
			break
		}

		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError("Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Space == "http://schemas.xmlsoap.org/soap/envelope/" && se.Name.Local == "Fault" {
				b.Fault = &SOAPFault{}
				b.Content = nil

				err = d.DecodeElement(b.Fault, &se)
				if err != nil {
					return err
				}

				consumed = true
			} else {
				if err = d.DecodeElement(b.Content, &se); err != nil {
					return err
				}

				consumed = true
			}
		case xml.EndElement:
			break Loop
		}
	}

	return nil
}

func (f *SOAPFault) Error() string {
	return f.String
}

func NewSOAPClient(url string, insecureSkipVerify bool, auth *BasicAuth) *SOAPClient {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
	}
	return NewSOAPClientWithTLSConfig(url, tlsCfg, auth)
}

func NewSOAPClientWithTLSConfig(url string, tlsCfg *tls.Config, auth *BasicAuth) *SOAPClient {
	return &SOAPClient{
		url:    url,
		tlsCfg: tlsCfg,
		auth:   auth,
	}
}

func (s *SOAPClient) AddHeader(header interface{}) {
	s.headers = append(s.headers, header)
}

func (s *SOAPClient) Call(soapAction string, request, response interface{}) error {
	envelope := new(SOAPEnvelope) //SOAPEnvelope{}
	envelope.XmlNS = "http://schemas.xmlsoap.org/soap/envelope/"

	if s.headers != nil && len(s.headers) > 0 {
		soapHeader := &SOAPHeader{Items: make([]interface{}, len(s.headers))}
		copy(soapHeader.Items, s.headers)
		envelope.Header = soapHeader
		envelope.Header.XmlNS = "http://schemas.xmlsoap.org/soap/envelope/"
	}

	envelope.Body.Content = request
	buffer := new(bytes.Buffer)

	encoder := xml.NewEncoder(buffer)
	//encoder.Indent("  ", "    ")

	if err := encoder.Encode(envelope); err != nil {
		return err
	}

	if err := encoder.Flush(); err != nil {
		return err
	}

	log.Println(buffer.String())

	req, err := http.NewRequest("POST", s.url, buffer)
	if err != nil {
		return err
	}
	if s.auth != nil {
		req.SetBasicAuth(s.auth.Login, s.auth.Password)
	}

	req.Header.Add("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Add("SOAPAction", soapAction)

	req.Header.Set("User-Agent", "gowsdl/0.1")
	req.Close = true

	tr := &http.Transport{
		TLSClientConfig: s.tlsCfg,
		Dial:            dialTimeout,
	}

	client := &http.Client{Transport: tr}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	rawbody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if len(rawbody) == 0 {
		log.Println("empty response")
		return nil
	}

	log.Println(string(rawbody))

	respEnvelope := new(ResponseSOAPEnvelope)
	respEnvelope.Body = ResponseSOAPBody{Content: response}
	err = xml.Unmarshal(rawbody, respEnvelope)
	if err != nil {
		return err
	}

	fault := respEnvelope.Body.Fault
	if fault != nil {
		return fault
	}

	return nil
}
