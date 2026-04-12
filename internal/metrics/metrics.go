// Package metrics fornece instrumentação OpenTelemetry para o TicketRadar.
// Expõe um endpoint /metrics compatível com Prometheus/Grafana Cloud.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics contém todos os contadores e gauges do TicketRadar.
type Metrics struct {
	// HTTP
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPDurationSeconds *prometheus.HistogramVec

	// Waitlist
	WaitlistTotal prometheus.Gauge

	// Monitor
	MonitorChecksTotal   *prometheus.CounterVec
	MonitorCheckDuration *prometheus.HistogramVec

	// Alertas
	AlertsSentTotal  *prometheus.CounterVec
	AlertsErrorTotal *prometheus.CounterVec

	reg *prometheus.Registry
}

// New cria e registra todas as métricas.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		reg: reg,

		HTTPRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ticketradar_http_requests_total",
				Help: "Total de requests HTTP por path, método e status.",
			},
			[]string{"path", "method", "status"},
		),

		HTTPDurationSeconds: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "ticketradar_http_duration_seconds",
				Help:    "Latência das requests HTTP em segundos.",
				Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5},
			},
			[]string{"path", "method"},
		),

		WaitlistTotal: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "ticketradar_waitlist_total",
				Help: "Total de usuários cadastrados na waitlist.",
			},
		),

		MonitorChecksTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ticketradar_monitor_checks_total",
				Help: "Total de verificações de eventos por label e status.",
			},
			[]string{"event", "status"},
		),

		MonitorCheckDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "ticketradar_monitor_check_duration_seconds",
				Help:    "Tempo de cada verificação de evento em segundos.",
				Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 10, 15},
			},
			[]string{"event"},
		),

		AlertsSentTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ticketradar_alerts_sent_total",
				Help: "Total de alertas enviados com sucesso por canal e evento.",
			},
			[]string{"channel", "event"},
		),

		AlertsErrorTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ticketradar_alerts_error_total",
				Help: "Total de erros no envio de alertas por canal.",
			},
			[]string{"channel"},
		),
	}

	reg.MustRegister(
		m.HTTPRequestsTotal,
		m.HTTPDurationSeconds,
		m.WaitlistTotal,
		m.MonitorChecksTotal,
		m.MonitorCheckDuration,
		m.AlertsSentTotal,
		m.AlertsErrorTotal,
		// Métricas padrão do Go runtime
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	return m
}

// Handler retorna o handler HTTP do /metrics (Prometheus format).
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}
