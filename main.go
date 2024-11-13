package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"httpheaders/internal/colorjson"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	requestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests by method and path",
		},
		[]string{"method", "path", "status"},
	)

	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	statusCodePattern = regexp.MustCompile(`^/statuscode/(\d{3})$`)
)

type Response struct {
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	Method     string            `json:"method"`
	Body       string            `json:"body"`
	Cookies    map[string]string `json:"cookies,omitempty"`
	Fresh      bool              `json:"fresh"`
	Hostname   string            `json:"hostname"`
	IP         string            `json:"ip"`
	IPs        []string          `json:"ips"`
	Protocol   string            `json:"protocol"`
	Query      map[string]string `json:"query"`
	Subdomains []string          `json:"subdomains"`
	XHR        bool              `json:"xhr"`
	OS         struct {
		Hostname string `json:"hostname"`
	} `json:"os"`
	Connection struct {
		Servername string `json:"servername"`
	} `json:"connection"`
	JSON interface{}       `json:"json,omitempty"`
	Env  map[string]string `json:"env,omitempty"`
}

type LogEntry struct {
	RemoteAddr string `json:"remote_addr"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Protocol   string `json:"protocol"`
	StatusCode int    `json:"status_code"`
	UserAgent  string `json:"user_agent"`
	Duration   string `json:"duration"`
	BytesOut   int    `json:"bytes_out"`
	Response   string `json:"response,omitempty"`
}

type ServerLog struct {
	Event   string `json:"event"`
	Message string `json:"message"`
	Port    string `json:"port,omitempty"`
	Error   string `json:"error,omitempty"`
}

type HttpCodeResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Settings struct {
	ServicePort          string `json:"service_port"`
	MetricsPort          string `json:"metrics_port"`
	HealthPort           string `json:"health_port"`
	PrometheusEnabled    bool   `json:"prometheus_enabled"`
	LogDisabled          bool   `json:"log_disabled"`
	PreserveHeaderCase   bool   `json:"preserve_header_case"`
	EchoEnv              bool   `json:"echo_env"`
	CorsOrigin           string `json:"cors_origin,omitempty"`
	CorsMethods          string `json:"cors_methods,omitempty"`
	CorsHeaders          string `json:"cors_headers,omitempty"`
	CorsCredentials      string `json:"cors_credentials,omitempty"`
	EchoBackToClient     bool   `json:"echo_back_to_client"`
	LogIgnorePath        string `json:"log_ignore_path,omitempty"`
	LogWithoutNewline    bool   `json:"log_without_newline"`
	OverrideResponsePath string `json:"override_response_path,omitempty"`
	ColorDisabled        bool   `json:"color_disabled"`
	JsonLogging          bool   `json:"json_logging"`
	LogResponse          bool   `json:"log_response"`
}

func jsonLog(entry interface{}) {
	logEntry := struct {
		Entry     interface{} `json:"entry"`
		Timestamp string      `json:"timestamp"`
	}{
		Entry:     entry,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	jsonBytes, _ := json.Marshal(logEntry)
	fmt.Println(string(jsonBytes))
}

func apacheLogFormat(entry LogEntry) string {
	timeStr := time.Now().Format("02/Jan/2006:15:04:05 -0700")
	requestLine := fmt.Sprintf("%s %s %s", entry.Method, entry.Path, entry.Protocol)
	return fmt.Sprintf("%s - - [%s] \"%s\" %d %d \"-\" \"%s\"",
		entry.RemoteAddr,
		timeStr,
		requestLine,
		entry.StatusCode,
		entry.BytesOut,
		entry.UserAgent,
	)
}

func extractIP(addr string) string {
	if net.ParseIP(addr) != nil {
		return addr
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func main() {
	port := os.Getenv("SERVICE_PORT")
	if port == "" {
		port = "8080"
	}

	metricsPort := os.Getenv("METRICS_PORT")
	if metricsPort == "" {
		metricsPort = "9090"
	}

	healthPort := os.Getenv("HEALTH_PORT")
	if healthPort == "" {
		healthPort = "8081"
	}

	colorDisabled := os.Getenv("DISABLE_COLOR_OUTPUT") == "true"
	corsCredentials := os.Getenv("CORS_ALLOW_CREDENTIALS")
	corsHeaders := os.Getenv("CORS_ALLOW_HEADERS")
	corsMethods := os.Getenv("CORS_ALLOW_METHODS")
	corsOrigin := os.Getenv("CORS_ALLOW_ORIGIN")
	echoBackToClient := os.Getenv("ECHO_BACK_TO_CLIENT") != "false"
	echoEnv := os.Getenv("ECHO_INCLUDE_ENV_VARS") == "true"
	jsonLogging := os.Getenv("JSON_LOGGING") == "true"
	logDisabled := os.Getenv("DISABLE_REQUEST_LOGS") == "true"
	logIgnorePath := os.Getenv("LOG_IGNORE_PATH")
	logResponse := os.Getenv("LOG_RESPONSE") == "true"
	logWithoutNewline := os.Getenv("LOG_WITHOUT_NEWLINE") == "true"
	overrideResponsePath := os.Getenv("OVERRIDE_RESPONSE_BODY_FILE_PATH")
	preserveHeaderCase := os.Getenv("PRESERVE_HEADER_CASE") == "true"
	prometheusEnabled := os.Getenv("PROMETHEUS_ENABLED") != "false"

	settings := Settings{
		ServicePort:          port,
		MetricsPort:          metricsPort,
		HealthPort:           healthPort,
		PrometheusEnabled:    prometheusEnabled,
		LogDisabled:          logDisabled,
		PreserveHeaderCase:   preserveHeaderCase,
		EchoEnv:              echoEnv,
		CorsOrigin:           corsOrigin,
		CorsMethods:          corsMethods,
		CorsHeaders:          corsHeaders,
		CorsCredentials:      corsCredentials,
		EchoBackToClient:     echoBackToClient,
		LogIgnorePath:        logIgnorePath,
		LogWithoutNewline:    logWithoutNewline,
		OverrideResponsePath: overrideResponsePath,
		ColorDisabled:        colorDisabled,
		JsonLogging:          jsonLogging,
		LogResponse:          logResponse,
	}

	if jsonLogging {
		jsonLog(struct {
			Event    string   `json:"event"`
			Settings Settings `json:"settings"`
		}{
			Event:    "settings",
			Settings: settings,
		})
	} else {
		log.Printf("Settings:\n"+
			"  Service Port: %s\n"+
			"  Metrics Port: %s\n"+
			"  Health Port: %s\n"+
			"  Prometheus Enabled: %v\n"+
			"  Log Disabled: %v\n"+
			"  Preserve Header Case: %v\n"+
			"  Echo Env: %v\n"+
			"  CORS Origin: %s\n"+
			"  CORS Methods: %s\n"+
			"  CORS Headers: %s\n"+
			"  CORS Credentials: %s\n"+
			"  Echo Back To Client: %v\n"+
			"  Log Ignore Path: %s\n"+
			"  Log Without Newline: %v\n"+
			"  Override Response Path: %s\n"+
			"  Color Disabled: %v\n"+
			"  JSON Logging: %v\n"+
			"  Log Response: %v\n",
			port, metricsPort, healthPort,
			prometheusEnabled, logDisabled,
			preserveHeaderCase, echoEnv,
			corsOrigin, corsMethods, corsHeaders,
			corsCredentials, echoBackToClient,
			logIgnorePath, logWithoutNewline,
			overrideResponsePath, colorDisabled,
			jsonLogging, logResponse)
	}

	hostname, _ := os.Hostname()

	mainHandler := func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		statusCode := http.StatusOK

		rr := &responseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			written:        0,
		}
		w = rr

		defer func() {
			duration := time.Since(start)

			if prometheusEnabled {
				requestsTotal.WithLabelValues(r.Method, r.URL.Path, fmt.Sprintf("%d", statusCode)).Inc()
				requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration.Seconds())
			}

			if !logDisabled && r.URL.Path != logIgnorePath {
				entry := LogEntry{
					RemoteAddr: extractIP(r.RemoteAddr),
					Method:     r.Method,
					Path:       r.URL.Path,
					Protocol:   r.Proto,
					StatusCode: rr.statusCode,
					UserAgent:  r.UserAgent(),
					Duration:   duration.String(),
					BytesOut:   rr.written,
				}

				if logResponse {
					entry.Response = rr.responseBody
				}

				if jsonLogging {
					jsonLog(struct {
						Event   string   `json:"event"`
						Request LogEntry `json:"request"`
					}{
						Event:   "request",
						Request: entry,
					})
				} else {
					log.Println(apacheLogFormat(entry))
				}
			}
		}()

		if matches := statusCodePattern.FindStringSubmatch(r.URL.Path); matches != nil {
			code, err := strconv.Atoi(matches[1])
			if err == nil && code >= 100 && code < 600 {
				statusCode = code
				resp := HttpCodeResponse{
					Code:    code,
					Message: http.StatusText(code),
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				json.NewEncoder(w).Encode(resp)
				return
			}
		}

		if overrideResponsePath != "" {
			http.ServeFile(w, r, overrideResponsePath)
			return
		}

		var bodyBytes []byte
		if r.Body != nil {
			var err error
			bodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				log.Printf("Error reading body: %v", err)
			}
		}

		headers := make(map[string]string)
		if preserveHeaderCase {
			for k, v := range r.Header {
				headers[k] = strings.Join(v, ", ")
			}
		} else {
			for k, v := range r.Header {
				headers[strings.ToLower(k)] = strings.Join(v, ", ")
			}
		}

		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = extractIP(r.RemoteAddr)
		}

		var ips []string
		if ip != "" {
			for _, ipStr := range strings.Split(ip, ",") {
				if cleaned := extractIP(strings.TrimSpace(ipStr)); cleaned != "" {
					ips = append(ips, cleaned)
				}
			}
		}

		response := Response{
			Path:     r.URL.Path,
			Headers:  headers,
			Method:   r.Method,
			Body:     string(bodyBytes),
			Fresh:    false,
			Hostname: r.Host,
			IP:       ip,
			IPs:      ips,
			Protocol: "http",
			Query:    make(map[string]string),
			OS: struct {
				Hostname string `json:"hostname"`
			}{
				Hostname: hostname,
			},
			Connection: struct {
				Servername string `json:"servername"`
			}{
				Servername: "",
			},
		}

		if echoEnv {
			response.Env = make(map[string]string)
			for _, env := range os.Environ() {
				pair := strings.SplitN(env, "=", 2)
				if len(pair) == 2 {
					response.Env[pair[0]] = pair[1]
				}
			}
		}

		for k, v := range r.URL.Query() {
			if len(v) > 0 {
				response.Query[k] = v[0]
			}
		}

		if status := r.Header.Get("X-Set-Response-Status-Code"); status != "" {
			if code, err := strconv.Atoi(status); err == nil && code >= 100 && code < 600 {
				statusCode = code
				w.WriteHeader(code)
			}
		}

		if delay := r.Header.Get("X-Set-Response-Delay-Ms"); delay != "" {
			if ms, err := strconv.Atoi(delay); err == nil && ms > 0 {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
		}

		var obj interface{}
		responseBytes, err := json.Marshal(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := json.Unmarshal(responseBytes, &obj); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if corsOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", corsOrigin)
			if corsMethods != "" {
				w.Header().Set("Access-Control-Allow-Methods", corsMethods)
			}
			if corsHeaders != "" {
				w.Header().Set("Access-Control-Allow-Headers", corsHeaders)
			}
			if corsCredentials != "" {
				w.Header().Set("Access-Control-Allow-Credentials", corsCredentials)
			}
		}

		if !echoBackToClient {
			return
		}

		if r.URL.Query().Get("response_body_only") == "true" {
			fmt.Fprint(w, string(bodyBytes))
			return
		}

		userAgent := strings.ToLower(r.UserAgent())
		isColorRequest := strings.HasPrefix(r.URL.Path, "/color")
		isCurl := strings.Contains(userAgent, "curl")
		acceptHeader := r.Header.Get("Accept")
		wantsJSON := strings.Contains(acceptHeader, "application/json")

		if isColorRequest && isCurl && !wantsJSON && !colorDisabled {
			w.Header().Set("Content-Type", "text/plain")
			formatter := colorjson.NewFormatter()

			formatter.ForceColor = true
			formatter.Indent = 2
			colored, err := formatter.Marshal(obj)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintln(w, string(colored))
		} else {
			w.Header().Set("Content-Type", "application/json")
			var output []byte
			if logWithoutNewline {
				output = responseBytes
			} else {
				output, err = json.MarshalIndent(obj, "", "  ")
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			w.Write(output)
			w.Write([]byte("\n"))
		}
	}

	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}

	mainServer := &http.Server{
		Addr:    ":" + port,
		Handler: http.HandlerFunc(mainHandler),
	}

	healthServer := &http.Server{
		Addr:    ":" + healthPort,
		Handler: http.HandlerFunc(healthHandler),
	}

	var metricsServer *http.Server
	if prometheusEnabled {
		metricsServer = &http.Server{
			Addr:    ":" + metricsPort,
			Handler: promhttp.Handler(),
		}
	}

	go func() {
		if jsonLogging {
			jsonLog(ServerLog{
				Event:   "startup",
				Message: "Starting main server",
				Port:    port,
			})
		} else {
			log.Printf("Starting main server on port %s", port)
		}
		if err := mainServer.ListenAndServe(); err != http.ErrServerClosed {
			if jsonLogging {
				jsonLog(ServerLog{
					Event:   "error",
					Message: "Main server error",
					Error:   err.Error(),
				})
			} else {
				log.Printf("Main server error: %v", err)
			}
		}
	}()

	go func() {
		if jsonLogging {
			jsonLog(ServerLog{
				Event:   "startup",
				Message: "Starting health check server",
				Port:    healthPort,
			})
		} else {
			log.Printf("Starting health check server on port %s", healthPort)
		}
		if err := healthServer.ListenAndServe(); err != http.ErrServerClosed {
			if jsonLogging {
				jsonLog(ServerLog{
					Event:   "error",
					Message: "Health check server error",
					Error:   err.Error(),
				})
			} else {
				log.Printf("Health check server error: %v", err)
			}
		}
	}()

	if prometheusEnabled {
		go func() {
			if jsonLogging {
				jsonLog(ServerLog{
					Event:   "startup",
					Message: "Starting metrics server",
					Port:    metricsPort,
				})
			} else {
				log.Printf("Starting metrics server on port %s", metricsPort)
			}
			if err := metricsServer.ListenAndServe(); err != http.ErrServerClosed {
				if jsonLogging {
					jsonLog(ServerLog{
						Event:   "error",
						Message: "Metrics server error",
						Error:   err.Error(),
					})
				} else {
					log.Printf("Metrics server error: %v", err)
				}
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop

	if jsonLogging {
		jsonLog(ServerLog{
			Event:   "shutdown",
			Message: "Shutting down servers",
		})
	} else {
		log.Println("Shutting down servers...")
	}

	mainServer.Close()
	healthServer.Close()
	if prometheusEnabled {
		metricsServer.Close()
	}
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode   int
	written      int
	responseBody string
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.written += n
	r.responseBody += string(b)
	return n, err
}
