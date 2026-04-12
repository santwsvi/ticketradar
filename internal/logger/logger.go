// Package logger fornece um writer que envia logs para o Better Stack (Logtail)
// via HTTP enquanto também escreve no stderr padrão.
// Configurado via env var BETTERSTACK_TOKEN.
// Se o token não estiver configurado, funciona apenas como logger padrão.
package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const betterstackEndpoint = "https://in.logs.betterstack.com"

type logEntry struct {
	Message string    `json:"message"`
	Level   string    `json:"level"`
	Service string    `json:"service"`
	DT      time.Time `json:"dt"`
}

// BetterstackWriter envia logs para o Better Stack em batches assíncronos.
type BetterstackWriter struct {
	token  string
	mu     sync.Mutex
	buf    []logEntry
	ticker *time.Ticker
	done   chan struct{}
}

func newWriter(token string) *BetterstackWriter {
	w := &BetterstackWriter{
		token:  token,
		done:   make(chan struct{}),
		ticker: time.NewTicker(5 * time.Second),
	}
	go w.flushLoop()
	return w
}

func (w *BetterstackWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg == "" {
		return len(p), nil
	}
	level := "info"
	low := strings.ToLower(msg)
	if strings.Contains(low, "erro") || strings.Contains(low, "error") ||
		strings.Contains(low, "fatal") || strings.Contains(low, "panic") {
		level = "error"
	} else if strings.Contains(low, "warn") || strings.Contains(msg, "⚠️") {
		level = "warn"
	}
	w.mu.Lock()
	w.buf = append(w.buf, logEntry{
		Message: msg, Level: level,
		Service: "ticketradar", DT: time.Now(),
	})
	w.mu.Unlock()
	return len(p), nil
}

func (w *BetterstackWriter) flush() {
	w.mu.Lock()
	if len(w.buf) == 0 {
		w.mu.Unlock()
		return
	}
	batch := make([]logEntry, len(w.buf))
	copy(batch, w.buf)
	w.buf = w.buf[:0]
	w.mu.Unlock()

	body, err := json.Marshal(batch)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", betterstackEndpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[logger] erro ao enviar logs para Better Stack: %v\n", err)
		return
	}
	resp.Body.Close()
}

func (w *BetterstackWriter) flushLoop() {
	for {
		select {
		case <-w.ticker.C:
			w.flush()
		case <-w.done:
			w.flush()
			return
		}
	}
}

func (w *BetterstackWriter) stop() {
	w.ticker.Stop()
	close(w.done)
}

// Setup configura o logger padrão.
// Se BETTERSTACK_TOKEN estiver setado, envia logs para o Better Stack E stderr.
// Retorna cleanup que deve ser chamado no defer do main.
func Setup() func() {
	token := os.Getenv("BETTERSTACK_TOKEN")
	log.SetFlags(log.Ldate | log.Ltime)

	if token == "" {
		log.SetOutput(os.Stderr)
		return func() {}
	}

	bsWriter := newWriter(token)
	log.SetOutput(io.MultiWriter(os.Stderr, bsWriter))
	log.Println("📡 Better Stack Logs conectado")

	return func() {
		bsWriter.stop()
	}
}
