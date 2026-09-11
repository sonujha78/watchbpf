package metrics

import (
	"net/http"
	"log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	EventsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "watchbpf_events_processed_total",
			Help: "Total kernel events processed, by type",
		},
		[]string{"event_type"},
	)

	EventsEscalated = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "watchbpf_events_escalated_total",
			Help: "Total events escalated past the baseline filter, by type",
		},
		[]string{"event_type"},
	)

	EventsRateLimited = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "watchbpf_events_rate_limited_total",
			Help: "Total escalations skipped due to rate limiting",
		},
	)

	LLMCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "watchbpf_llm_calls_total",
			Help: "Total LLM calls, by backend and result (success/error)",
		},
		[]string{"backend", "result"},
	)

	Decisions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "watchbpf_decisions_total",
			Help: "Total policy decisions, by tier",
		},
		[]string{"tier"},
	)

	Actions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "watchbpf_actions_total",
			Help: "Total enforcement actions taken, by type (kill/pause/isolate) and mode (dry-run/live)",
		},
		[]string{"action", "mode"},
	)
)

func init() {
	prometheus.MustRegister(EventsProcessed, EventsEscalated, EventsRateLimited, LLMCalls, Decisions, Actions)
}

// StartServer /metrics endpoint ko background mein start karta hai
func StartServer(addr string) {
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		log.Printf("Metrics server listening on %s/metrics", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("metrics server error: %v", err)
		}
	}()
}
