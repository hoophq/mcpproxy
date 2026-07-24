package approval

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// API serves the reviewer-facing HTTP surface of a [Store]. The daemon mounts
// it under /approvals; every route below is relative to that mount point:
//
//	GET  /            → 200, JSON array of PendingView (oldest first)
//	GET  /{id}        → 200 PendingView, or 404
//	POST /{id}/approve → 204, 404 (unknown id), 409 (already resolved)
//	POST /{id}/reject  → 204, 404, 409
//
// Anything else under the mount is a 404; a wrong method on a known route is a
// 405 with an Allow header.
type API struct {
	store *Store
	token string
	log   *slog.Logger
	mux   *http.ServeMux
}

// NewAPI wraps store in an http.Handler guarded by a bearer token.
//
// An empty token disables the guard entirely: the daemon owns that policy
// decision (it may be fronting the API with its own auth, or binding it to
// loopback). Comparison is constant-time so the endpoint cannot be used as a
// token oracle.
func NewAPI(store *Store, token string) *API {
	a := &API{store: store, token: token, log: slog.Default(), mux: http.NewServeMux()}
	// Go 1.22+ pattern routing: method and wildcards are matched for us, so a
	// bad method yields 405 with Allow rather than a hand-rolled 404.
	a.mux.HandleFunc("GET /{$}", a.handleList)
	a.mux.HandleFunc("GET /{id}", a.handleGet)
	a.mux.HandleFunc("POST /{id}/approve", a.handleResolve(true))
	a.mux.HandleFunc("POST /{id}/reject", a.handleResolve(false))
	return a
}

// WithLogger returns a shallow copy logging to l. nil is ignored.
func (a *API) WithLogger(l *slog.Logger) *API {
	if l == nil {
		return a
	}
	b := *a
	b.log = l
	return &b
}

// ServeHTTP authenticates, then routes.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !a.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcpproxy approvals"`)
		writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
		return
	}
	a.mux.ServeHTTP(w, r)
}

// authorized reports whether r carries the configured bearer token. With no
// token configured every request passes.
func (a *API) authorized(r *http.Request) bool {
	if a.token == "" {
		return true
	}
	presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(presented)), []byte(a.token)) == 1
}

func (a *API) handleList(w http.ResponseWriter, r *http.Request) {
	a.writeJSON(w, r, http.StatusOK, a.store.List())
}

func (a *API) handleGet(w http.ResponseWriter, r *http.Request) {
	v, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "no such pending call")
		return
	}
	a.writeJSON(w, r, http.StatusOK, v)
}

// handleResolve builds the approve/reject handlers; they differ only in the
// verdict they hand the store.
func (a *API) handleResolve(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		err := a.store.Resolve(id, approve)
		switch {
		case err == nil:
			a.log.InfoContext(r.Context(), "approval resolved",
				"approval_id", id, "approved", approve)
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "no such pending call")
		case errors.Is(err, ErrAlreadyResolved):
			writeError(w, http.StatusConflict, "call already resolved")
		default:
			a.log.ErrorContext(r.Context(), "approval resolve failed",
				"approval_id", id, "err", err)
			writeError(w, http.StatusInternalServerError, "resolve failed")
		}
	}
}

func (a *API) writeJSON(w http.ResponseWriter, r *http.Request, code int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// Encoding our own projection cannot normally fail; if it does, say so
		// before any bytes are committed rather than truncating the response.
		a.log.ErrorContext(r.Context(), "approval encode failed", "err", err)
		writeError(w, http.StatusInternalServerError, "encode failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(append(body, '\n'))
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
