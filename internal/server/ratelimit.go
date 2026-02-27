package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimitPerIP returns middleware that applies per-IP rate limiting.
// Each unique IP gets its own token bucket with the given rate and burst.
// Stale entries are cleaned up every minute.
func RateLimitPerIP(r rate.Limit, burst int) func(http.Handler) http.Handler {
	var mu sync.Mutex
	limiters := make(map[string]*ipLimiter)

	// Background cleanup of stale entries
	go func() {
		for {
			time.Sleep(time.Minute)
			mu.Lock()
			for ip, l := range limiters {
				if time.Since(l.lastSeen) > 3*time.Minute {
					delete(limiters, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ip := clientIP(req)

			mu.Lock()
			l, ok := limiters[ip]
			if !ok {
				l = &ipLimiter{limiter: rate.NewLimiter(r, burst)}
				limiters[ip] = l
			}
			l.lastSeen = time.Now()
			mu.Unlock()

			if !l.limiter.Allow() {
				w.Header().Set("Retry-After", "1")
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}

// clientIP extracts the client IP, preferring X-Forwarded-For (first entry).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); ip != "" {
			return ip
		}
	}
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}
