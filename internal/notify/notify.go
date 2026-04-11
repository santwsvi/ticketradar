package notify

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

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

// SendAllToUser tenta enviar email para um usuário específico com retry (máx 3 tentativas).
// Sprint 2: backoff progressivo — 0s, 30s, 5min — para lidar com falhas transientes de SMTP.
// Apenas email por ora (SMS é caro para muitos usuários).
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
		return nil // sucesso
	}
	return fmt.Errorf("todas as %d tentativas falharam: %w", len(delays), lastErr)
}

// maskEmailLog — helper local para mascarar email em logs de retry.
// Usa apenas os 2 primeiros caracteres do local-part para máxima privacidade.
// C5: evita exposição de PII em logs de produção (LGPD Art. 46).
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

// SendEmail envia alerta via Gmail SMTP para o destinatário configurado em cfg.EmailTo
func SendEmail(cfg Config, alert Alert) error {
	return SendEmailToUser(cfg, cfg.EmailTo, alert)
}

// SendEmailToUser envia alerta de disponibilidade para um destinatário específico.
// Sprint 2: permite notificar cada usuário da waitlist individualmente.
func SendEmailToUser(cfg Config, toEmail string, alert Alert) error {
	if toEmail == "" {
		return fmt.Errorf("destinatário de email não definido")
	}

	m := gomail.NewMessage()
	m.SetHeader("From", cfg.EmailFrom)
	m.SetHeader("To", toEmail)
	m.SetHeader("Subject", fmt.Sprintf("🎟️ DISPONÍVEL: %s", alert.EventLabel))

	body := fmt.Sprintf(`CORRE! Detectamos disponibilidade para %s

Acesse agora:
%s

Status: %s
Detectado às: %s

---
Para cancelar sua inscrição, acesse:
DELETE /api/waitlist?email=%s

TicketRadar — Você dormiu. A gente não.`,
		alert.EventLabel, alert.EventURL, alert.Status, alert.DetectedAt, toEmail)

	m.SetBody("text/plain", body)

	d := gomail.NewDialer("smtp.gmail.com", 587, cfg.EmailFrom, cfg.EmailPassword)
	return d.DialAndSend(m)
}

// SendWelcomeEmail envia email de boas-vindas ao usuário recém-cadastrado na waitlist.
// Confirma o cadastro, explica o produto e instrui como cancelar (LGPD Art. 18, IV).
func SendWelcomeEmail(cfg Config, toEmail, name string) error {
	if toEmail == "" {
		return fmt.Errorf("destinatário de email não definido")
	}

	displayName := name
	if displayName == "" {
		displayName = "por aí"
	}

	m := gomail.NewMessage()
	m.SetHeader("From", cfg.EmailFrom)
	m.SetHeader("To", toEmail)
	m.SetHeader("Subject", "🎟️ Você está na lista do TicketRadar!")

	body := fmt.Sprintf(`Oi, %s!

Seu cadastro no TicketRadar foi confirmado. 🎉

O que acontece agora:
• Monitoramos a disponibilidade dos ingressos automaticamente, 24/7.
• Quando detectarmos que os ingressos abriram, você recebe um email imediatamente.
• Sem spam. Só alertas reais quando os ingressos estiverem disponíveis.

Quer sair da lista? Sem problema.
Envie uma requisição DELETE para:
  DELETE /api/waitlist?email=%s
(com o header X-Delete-Token fornecido no cadastro)

Boa sorte na fila! 🎟️

---
TicketRadar — Você dormiu. A gente não.`,
		displayName, toEmail)

	m.SetBody("text/plain", body)

	d := gomail.NewDialer("smtp.gmail.com", 587, cfg.EmailFrom, cfg.EmailPassword)
	return d.DialAndSend(m)
}
