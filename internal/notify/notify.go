package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config contém as credenciais de notificação
type Config struct {
	// Email — Resend API (HTTPS, sem SMTP)
	ResendAPIKey string
	EmailFrom    string
	EmailTo      string

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

// resendPayload é o body da API do Resend
type resendPayload struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Text    string   `json:"text"`
}

// sendViaResend envia email usando a API HTTP do Resend (porta 443 — sem SMTP)
// Funciona no Railway free tier que bloqueia saída na porta 587.
func sendViaResend(apiKey, from, to, subject, body string) error {
	if apiKey == "" {
		return fmt.Errorf("RESEND_API_KEY não configurado")
	}
	if to == "" {
		return fmt.Errorf("destinatário não definido")
	}

	payload := resendPayload{
		From:    from,
		To:      []string{to},
		Subject: subject,
		Text:    body,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("serializar payload: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("criar request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("chamada API Resend: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("Resend retornou %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// fromAddress retorna o endereço remetente formatado.
// Resend exige domínio verificado para remetentes customizados.
// Enquanto não há domínio verificado, usa o endereço padrão do Resend.
func fromAddress(cfg Config) string {
	// Se EMAIL_FROM for de domínio verificado no Resend, usa ele.
	// Caso contrário, usa o endereço de teste do Resend (funciona sem verificação).
	if cfg.EmailFrom != "" && !strings.HasSuffix(cfg.EmailFrom, "@gmail.com") {
		return "TicketRadar <" + cfg.EmailFrom + ">"
	}
	return "TicketRadar <onboarding@resend.dev>"
}

// SendAll envia alerta por todos os canais configurados em paralelo.
func SendAll(cfg Config, alert Alert) []error {
	type result struct{ err error }

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

// SendAllToUser tenta enviar email para um usuário específico com retry (máx 3 tentativas).
// Backoff progressivo: 0s → 30s → 5min.
func SendAllToUser(cfg Config, toEmail string, alert Alert) error {
	var lastErr error
	delays := []time.Duration{0, 30 * time.Second, 5 * time.Minute}

	for i, delay := range delays {
		if delay > 0 {
			time.Sleep(delay)
		}
		if err := SendEmailToUser(cfg, toEmail, alert); err != nil {
			lastErr = err
			log.Printf("tentativa %d/%d falhou para %s: %v", i+1, len(delays), maskEmailLog(toEmail), err)
			continue
		}
		return nil
	}
	return fmt.Errorf("todas as %d tentativas falharam: %w", len(delays), lastErr)
}

// maskEmailLog mascara email para logs — 2 chars + *** + @domínio
func maskEmailLog(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || len(parts[0]) <= 2 {
		return "***"
	}
	return parts[0][:2] + "***@" + parts[1]
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

// SendEmail envia alerta para o destinatário configurado em cfg.EmailTo
func SendEmail(cfg Config, alert Alert) error {
	return SendEmailToUser(cfg, cfg.EmailTo, alert)
}

// SendEmailToUser envia alerta de disponibilidade para um destinatário específico via Resend.
func SendEmailToUser(cfg Config, toEmail string, alert Alert) error {
	subject := fmt.Sprintf("🎟️ DISPONÍVEL: %s", alert.EventLabel)
	body := fmt.Sprintf(`CORRE! Detectamos disponibilidade para %s

Acesse agora:
%s

Status: %s
Detectado às: %s

---
Para cancelar sua inscrição: privacidade@ticketradar.app

TicketRadar — Você dormiu. A gente não.`,
		alert.EventLabel, alert.EventURL, alert.Status, alert.DetectedAt)

	return sendViaResend(cfg.ResendAPIKey, fromAddress(cfg), toEmail, subject, body)
}

// SendWelcomeEmail envia email de boas-vindas ao usuário recém-cadastrado via Resend.
func SendWelcomeEmail(cfg Config, toEmail, name string) error {
	displayName := name
	if displayName == "" {
		displayName = "por aí"
	}

	subject := "🎟️ Você está na lista do TicketRadar!"
	body := fmt.Sprintf(`Oi, %s! 👋

Seu cadastro no TicketRadar foi confirmado. 🎉

O que acontece agora:
• Monitoramos a disponibilidade dos ingressos 24/7, a cada 30 segundos.
• Quando detectarmos que ingressos abriram, você recebe um alerta imediatamente.
• Sem spam. Só alertas reais.

Quer sair da lista? Manda um email para: privacidade@ticketradar.app

Boa sorte na fila! 🎟️

---
TicketRadar — Você dormiu. A gente não.`, displayName)

	return sendViaResend(cfg.ResendAPIKey, fromAddress(cfg), toEmail, subject, body)
}
