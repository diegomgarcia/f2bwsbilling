# Payment XML API Go client
 
This is a client for the F2B XML API ([https://www.f2b.com.br/desenvolvedores/](https://www.f2b.com.br/desenvolvedores/)

## Goals

- [ ] Automated tests that don't require manual approval in F2B account
- [ ] Automated tests that require manual approval in a F2B account 
- [ ] Add get payment status from the F2B status webservice

## Usage

```bash
go get github.com/diegomgarcia/f2bwsbilling
```

Import into your app and start using it:

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/diegomgarcia/f2bwsbilling"
)

func main() {

  clientID := os.Getenv("F2B_CLIENTID")
  if clientID == "" {
     panic("F2B clientID is missing")
  }

  ownerName := os.Getenv("F2B_OWNERNAME")
  if secret == "" {
     panic("F2B ownerName is missing")
  }

  cobranca := &f2bwsbilling.F2bCobranca{}
  cobranca.XmlNS = "http://www.f2b.com.br/soap/wsbilling.xsd"

  cobranca.Mensagem.Numero = "" //Your own document identification number
  cobranca.Mensagem.Data = time.Now().Format("2006-01-02")
  cobranca.Mensagem.Tipo_ws = "WebService"

  cobranca.Sacador.Conta = clientID
  cobranca.Sacador.Value = ownerName

  cobranca.Cobranca.Num_document = 0
  cobranca.Cobranca.Tipo_cobranca = "" //C= Cartao Credito B= Boleto D= Debito T= Transferencia Online "" = Todos

  demonstrativo := []string{ "Description: xxxx " , "Another line of description ..."}
  
  cobranca.Cobranca.Demonstrativo = demonstrativo

  cobranca.Cobranca.Valor = inscricao.ValorEvento()
  cobranca.Agendamento.Vencimento = time.Now().AddDate(0, 0, 3).Format("2006-01-02")
  cobranca.Agendamento.Value = ""

  Sacado := f2bwsbilling.Sacado{}
  Sacado.Grupo = inscricao.NomeEvento()

  Sacado.Nome = inscricao.Nome
  Sacado.Cpf = inscricao.Cpf
  Sacado.Email = inscricao.Email
  Sacado.Envio = "e"     //e = email, p = correios, b = ambos, n = nenhum
  Sacado.Atualizar = "s" //s = sim, n = não

  Sacados := []f2bwsbilling.Sacado{Sacado}

  cobranca.Sacado = Sacados

  client := f2bwsbilling.NewWSBillingPortType("http://www.f2b.com.br/WSBilling", false, nil)
	result, err := client.RegisterWSBilling(cobranca)
  
  if err != nil {
    log.Fatal(err)
  }
  
  log.Print(result)
  
  log.Print(result.Cobranca[0].Url) //This return the Url that your customer can pay your document.
  
}
```

## Roadmap

- [x] [Payments - Register](https://www.f2b.com.br/desenvolvedores/)
- [ ] [Payments - Get Status](https://www.f2b.com.br/desenvolvedores/)
