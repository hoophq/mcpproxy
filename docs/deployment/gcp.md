# Deploying mcpproxy on GCP

Read [README.md](README.md) first: the daemon is single-replica by
construction, and that shapes every choice below. Build the image with
[container.md](container.md).

Two options:

| | Cloud Run | GKE |
|---|---|---|
| TLS + managed certs | built in | needs Ingress/Gateway + ManagedCertificate |
| Scale to zero | yes, but see below | no |
| Session affinity | on/off switch, cookie-based | `HEADER_FIELD` on the backend service |
| Persistent state | GCS FUSE or Filestore | PersistentVolumeClaim |
| Best for | remote backends, static/OIDC inbound | stdio backends, approvals, auth server |

Pick Cloud Run for a remote-backend gateway. Pick GKE if you need stdio
backends at volume, approvals, or the embedded auth server.

## Cloud Run

### What works

`listen: 0.0.0.0:${PORT}` — Cloud Run injects `PORT`, and the config
expands `${VAR}` at load, so no wrapper script is needed. Verified: the
daemon logs `addr=0.0.0.0:8080`.

### Pin it to one instance

```sh
gcloud run deploy mcpproxy \
  --image=REGION-docker.pkg.dev/PROJECT/repo/mcpproxy:TAG \
  --region=REGION \
  --min-instances=1 \
  --max-instances=1 \
  --no-cpu-throttling \
  --timeout=3600 \
  --port=8080 \
  --set-env-vars=MCPPROXY_STATE_DIR=/var/lib/mcpproxy \
  --set-secrets=MCPPROXY_APPROVAL_TOKEN=mcpproxy-approval-token:latest
```

Every flag above is load-bearing:

- `--max-instances=1`. Cloud Run's session affinity is best-effort and
  cookie-based; MCP clients send no cookies. Without this cap you get
  intermittent `404 unknown session` as requests spread across instances.
- `--min-instances=1`. Scaling to zero destroys every live session, all
  pending approvals, and the auth server's in-memory state.
- `--no-cpu-throttling`. Cloud Run throttles CPU outside a request by
  default. The daemon runs background work between requests — the session
  reaper, backend pumps that deliver server-initiated SSE traffic, and
  OAuth refresh. Throttled, an SSE notification stalls until the next
  inbound request.
- `--timeout=3600`. The default 300s kills the `GET /mcp` SSE stream.

Even so, Cloud Run may replace the instance for maintenance, which drops
sessions. Clients re-`initialize` and recover; approvals in flight do not.

### State

Cloud Run's filesystem is ephemeral. For `auth: oauth` backends, mount
durable storage or the daemon regenerates `tokens.key` and then **fails to
boot** against a surviving `tokens.enc`:

```sh
gcloud run services update mcpproxy \
  --add-volume=name=state,type=cloud-storage,bucket=my-mcpproxy-state \
  --add-volume-mount=volume=state,mount-path=/var/lib/mcpproxy
```

GCS FUSE is not POSIX-complete. It handles this workload because the daemon
writes with temp-file + rename and only two small files are involved, but
**never point two services at the same bucket path** — there is no file
lock, and concurrent writers clobber grants.

Simpler: avoid `auth: oauth` on Cloud Run. Use `auth: static` with a
Secret Manager secret, or token exchange. The loopback OAuth flow needs a
browser on the daemon's host and cannot complete headless anyway.

### Health checks

```sh
gcloud run services update mcpproxy \
  --liveness-probe=httpGet.path=/healthz,initialDelaySeconds=5,periodSeconds=30
```

Do not add a startup probe that expects backends to be reachable.
`/healthz` reports process liveness only, which is what you want: a dead
backend should end one session, not restart the daemon.

### Inbound auth

Cloud Run IAM (`--no-allow-unauthenticated`) authenticates the *caller
service account*, not the MCP user. That is a useful outer perimeter, but
identity in audit events and per-user token grants still comes from
`inbound.mode`. Set both.

## GKE

### Single-replica Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcpproxy
spec:
  # Not a placeholder. Sessions, approvals and auth-server state are all
  # in-process; a second replica serves 404s for the first one's sessions.
  replicas: 1
  strategy:
    # Never run two pods at once: the old pod owns live sessions and the
    # new one cannot see them.
    type: Recreate
  selector:
    matchLabels: { app: mcpproxy }
  template:
    metadata:
      labels: { app: mcpproxy }
    spec:
      # Backends get SIGTERM, then SIGKILL after a 3s grace, serialised per
      # session, after a 10s HTTP drain. Too short a window truncates WAL
      # records and can orphan stdio children.
      terminationGracePeriodSeconds: 90
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
      containers:
        - name: mcpproxy
          image: REGION-docker.pkg.dev/PROJECT/repo/mcpproxy:TAG
          ports: [{ containerPort: 8080 }]
          env:
            - name: PORT
              value: "8080"
            - name: MCPPROXY_STATE_DIR
              value: /var/lib/mcpproxy
            - name: MCPPROXY_APPROVAL_TOKEN
              valueFrom:
                secretKeyRef: { name: mcpproxy, key: approval-token }
          volumeMounts:
            - { name: state, mountPath: /var/lib/mcpproxy }
            - { name: config, mountPath: /etc/mcpproxy }
          livenessProbe:
            httpGet: { path: /healthz, port: 8080 }
            periodSeconds: 30
          readinessProbe:
            httpGet: { path: /healthz, port: 8080 }
            periodSeconds: 10
          resources:
            requests: { cpu: 500m, memory: 512Mi }
            # Live child processes = sessions x stdio backends, not pooled.
            limits: { memory: 2Gi }
      volumes:
        - name: state
          persistentVolumeClaim: { claimName: mcpproxy-state }
        - name: config
          configMap: { name: mcpproxy-config }
```

The PVC must be `ReadWriteOnce`. `ReadWriteMany` invites a second writer,
which corrupts the grant store.

Do not add a HorizontalPodAutoscaler. Scale the pod, not the replica count.

### If you genuinely need more than one replica

Only viable when **all** of the following hold: no approvals, no embedded
auth server, and each replica gets its own state volume (a StatefulSet with
`volumeClaimTemplates`). Then hash on the session header:

```yaml
apiVersion: cloud.google.com/v1
kind: BackendConfig
metadata:
  name: mcpproxy
spec:
  sessionAffinity:
    affinityType: "HEADER_FIELD"
  timeoutSec: 3600          # SSE streams outlive the 30s default
  connectionDraining:
    drainingTimeoutSec: 90
```

`HEADER_FIELD` affinity hashes on `consistentHash.httpHeaderName` and
requires `localityLbPolicy: RING_HASH` or `MAGLEV`; consistent hashing is
supported on `INTERNAL_MANAGED` and `INTERNAL_SELF_MANAGED` backend
services, so check that your load balancer flavour supports it before
relying on this. Set the header name to `Mcp-Session-Id`.

This still leaves a hole: `initialize` carries no session header, so the
first request hashes on an absent value. Sessions land somewhere and stay
there, which is what matters, but distribution is uneven.

### SSE and idle timeouts

The `GET /mcp` stream sends bytes only when the server has something to
say, with no keepalive frames. An idle stream can be closed by any
intermediary. Set `timeoutSec` above your expected idle gap; the session
reaper's 30-minute timeout is hardcoded and not configurable, so 3600 is a
safe ceiling.

### TLS and the OIDC discovery caveat

Terminate TLS at the Ingress or Gateway; the daemon is plaintext only.

If you use `inbound.mode: oidc` without `auth_server`, the daemon
advertises its RFC 9728 resource identifier as `"http://" + listen`, so
clients discover `http://0.0.0.0:8080`. There is no override. Configure
clients with the issuer directly.

## Observability

Scrape `/metrics` when `telemetry.prometheus_path` is set:

```yaml
apiVersion: monitoring.googleapis.com/v1
kind: PodMonitoring
metadata:
  name: mcpproxy
spec:
  selector:
    matchLabels: { app: mcpproxy }
  endpoints:
    - port: 8080
      path: /metrics
      interval: 30s
```

Alert on `mcpproxy_messages_total{decision="kill"}`. Do not alert on
`mcpproxy_sessions_active` — it always reads 0 (see
[README.md](README.md)).

For traces, set `telemetry.otlp_endpoint` to an OpenTelemetry Collector
exporting to Cloud Trace.
