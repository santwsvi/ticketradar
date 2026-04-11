package notify

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"gopkg.in/gomail.v2"
)

// Config contém as credenciais de notificação
type Config struct {
	// Email
	EmailFrom     string
	EmailPassword string
	EmailTo       string

	// Twilio SMS
	TwilioSID   string
	TwilioToken string
	TwilioFrom  string
	TwilioTo    string
}

// Alert representa um alerta a ser enviado
type Alert struct {
	EventLabel string
	EventURL   string
	Status     string
	DetectedAt string
}

// SendAll envia alerta por todos os canais configurados em paralelo.
// M1: SMS e Email são disparados concorrentemente via goroutines + WaitGroup.
// Erros são coletados via channel com buffer para evitar goroutine leak.
func SendAll(cfg Config, alert Alert) []error {
	type result struct {
		err error
	}

	// Buffer igual ao número de canais — nunca bloqueia o sender
	ch := make(chan result, 2)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := SendSMS(cfg, alert); err != nil {
			ch <- result{fmt.Errorf("sms: %w", err)}
		} else {
			ch <- result{}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := SendEmail(cfg, alert); err != nil {
			ch <- result{fmt.Errorf("email: %w", err)}
		} else {
			ch <- result{}
		}
	}()

	// Fecha o canal após ambas as goroutines terminarem
	go func() {
		wg.Wait()
		close(ch)
	}()

	var errs []error
	for r := range ch {
		if r.err != nil {
			errs = append(errs, r.err)
		}
	}
	return errs
}

// SendSMS envia alerta via Twilio
func SendSMS(cfg Config, alert Alert) error {
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", cfg.TwilioSID)

	msg := fmt.Sprintf("🎟️ CORRE! %s disponível!\n%s", alert.EventLabel, alert.EventURL)

	data := url.Values{}
	data.Set("From", cfg.TwilioFrom)
	data.Set("To", cfg.TwilioTo)
	data.Set("Body", msg)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(cfg.TwilioSID, cfg.TwilioToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("twilio retornou status %d", resp.StatusCode)
	}

	return nil
}

// SendEmail envia alerta via Gmail SMTP
func SendEmail(cfg Config, alert Alert) error {
	m := gomail.NewMessage()
	m.SetHeader("From", cfg.EmailFrom)
	m.SetHeader("To", cfg.EmailTo)
	m.SetHeader("Subject", fmt.Sprintf("🎟️ DISPONÍVEL: %s", alert.EventLabel))

	body := fmt.Sprintf(`CORRE! Detectamos disponibilidade para %s

Acesse agora:
%s

Status: %s
Detectado às: %s

---
TicketRadar — Você dormiu. A gente não.`,
		alert.EventLabel, alert.EventURL, alert.Status, alert.DetectedAt)

	m.SetBody("text/plain", body)

	d := gomail.NewDialer("smtp.gmail.com", 587, cfg.EmailFrom, cfg.EmailPassword)

	return d.DialAndSend(m)
}
