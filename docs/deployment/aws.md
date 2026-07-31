# Deploying mcpproxy on AWS

Read [README.md](README.md) first: the daemon is single-replica by
construction, and that shapes every choice below. Build the image with
[container.md](container.md).

Two options:

| | ECS Fargate | EKS |
|---|---|---|
| Ops burden | low | high |
| Persistent state | EFS access point | PVC (EBS) |
| Session affinity | not achievable via ALB | not achievable via ALB |
| Best for | most deployments | you already run EKS |

**Neither can safely run more than one task.** The reason is specific to
AWS and worth stating plainly.

## ALB stickiness does not work for MCP

ALB target-group stickiness is cookie-based in both forms: load-balancer
generated (`AWSALB`) and application-based. Both require the client to
store and return a `Set-Cookie` value.

MCP clients are not browsers. They will not return the cookie, so every
request hashes fresh and lands on an arbitrary target. Post-`initialize`
requests then hit a task that has never heard of the session and get
`404 unknown session`.

ALB offers no request-header-based routing to a *specific* target — only
listener rules that select a target group, which does not identify a
task. There is no configuration that makes multi-task mcpproxy correct
behind an ALB.

**Run exactly one task.** Scale vertically.

## ECS Fargate

### Task definition

```json
{
  "family": "mcpproxy",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "runtimePlatform": { "cpuArchitecture": "ARM64", "operatingSystemFamily": "LINUX" },
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/mcpproxyTaskRole",
  "volumes": [
    {
      "name": "state",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-XXXX",
        "transitEncryption": "ENABLED",
        "authorizationConfig": { "accessPointId": "fsap-XXXX", "iam": "ENABLED" }
      }
    }
  ],
  "containerDefinitions": [
    {
      "name": "mcpproxy",
      "image": "ACCOUNT.dkr.ecr.REGION.amazonaws.com/mcpproxy:TAG",
      "portMappings": [{ "containerPort": 8080, "protocol": "tcp" }],
      "environment": [
        { "name": "PORT", "value": "8080" },
        { "name": "MCPPROXY_STATE_DIR", "value": "/var/lib/mcpproxy" }
      ],
      "secrets": [
        {
          "name": "MCPPROXY_APPROVAL_TOKEN",
          "valueFrom": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:mcpproxy-approval-token"
        }
      ],
      "mountPoints": [
        { "sourceVolume": "state", "containerPath": "/var/lib/mcpproxy", "readOnly": false }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "node -e 'require(\"http\").get(\"http://localhost:8080/healthz\",r=>process.exit(r.statusCode===200?0:1)).on(\"error\",()=>process.exit(1))'"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 10
      },
      "stopTimeout": 90,
      "linuxParameters": { "initProcessEnabled": true },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/mcpproxy",
          "awslogs-region": "REGION",
          "awslogs-stream-prefix": "mcpproxy"
        }
      }
    }
  ]
}
```

Three fields deserve explanation:

- **`stopTimeout: 90`** (max 120 on Fargate). ECS sends `SIGTERM`, waits,
  then `SIGKILL`s. The daemon drains HTTP for 10s, then tears down each
  session's backends with a 3s grace before `SIGKILL`, serialised per
  session. The default 30s can cut that short, truncating WAL records.
- **`initProcessEnabled: true`**. Each session spawns a process tree
  (`npm exec` → `sh` → `node` for an `npx` backend). The daemon
  process-group kills them, but an init process reaps any stragglers
  instead of leaving zombies to accumulate against the task's pid budget.
- **`healthCheck` uses `node`, not `curl`.** `node:22-slim` ships no curl,
  so a `curl -fsS` probe fails every time and ECS kills a healthy task.
  Node is guaranteed present on that base. On a distroless image there is
  no shell at all — drop the container health check and rely on the ALB
  target-group check instead.

### Service

```sh
aws ecs create-service \
  --cluster mcpproxy \
  --service-name mcpproxy \
  --task-definition mcpproxy \
  --desired-count 1 \
  --launch-type FARGATE \
  --deployment-configuration 'maximumPercent=100,minimumHealthyPercent=0' \
  --health-check-grace-period-seconds 30 \
  --network-configuration 'awsvpcConfiguration={subnets=[subnet-XXXX],securityGroups=[sg-XXXX]}'
```

`maximumPercent=100` with `minimumHealthyPercent=0` forces stop-then-start.
The rolling default would briefly run two tasks, and during that overlap
the ALB splits traffic between a task holding live sessions and a new one
that 404s them. A brief outage is the honest tradeoff for a daemon whose
sessions cannot migrate.

### EFS for state

Only needed for `auth: oauth` backends. Use an access point with the
container's uid so the daemon can create `0700` directories:

```sh
aws efs create-access-point --file-system-id fs-XXXX \
  --posix-user 'Uid=10001,Gid=10001' \
  --root-directory 'Path=/mcpproxy,CreationInfo={OwnerUid=10001,OwnerGid=10001,Permissions=0700}'
```

Never mount one access point into two tasks. The grant store has no file
lock; concurrent writers clobber each other last-writer-wins, and both run
refresh loops against the same rotating refresh token.

Consider skipping EFS entirely: `auth: static` from Secrets Manager, or
token exchange, avoids durable state. The interactive OAuth flow needs a
loopback browser and cannot complete in Fargate regardless.

### ALB

```sh
# SSE streams send no keepalive; the 60s default closes idle streams.
aws elbv2 modify-load-balancer-attributes --load-balancer-arn ARN \
  --attributes Key=idle_timeout.timeout_seconds,Value=3600

aws elbv2 modify-target-group-attributes --target-group-arn ARN \
  --attributes Key=deregistration_delay.timeout_seconds,Value=90
```

Target-group health check: path `/healthz`, matcher `200`, interval 30s.

Terminate TLS on the ALB with an ACM certificate; the daemon is plaintext
only. Restrict the task security group to the ALB security group.

### IAM

`inbound.mode: awssts` validates a caller's signed STS identity against
`aws_role_mappings`, needing no AWS credentials on the task. The task role
is only for pulling secrets and mounting EFS. Grant nothing else.

## EKS

Use the GKE Deployment manifest in [gcp.md](gcp.md) — it is portable — with
these substitutions:

- `storageClassName: gp3` on the PVC, `ReadWriteOnce`.
- AWS Load Balancer Controller ingress annotations:

```yaml
metadata:
  annotations:
    alb.ingress.kubernetes.io/scheme: internal
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/healthcheck-path: /healthz
    alb.ingress.kubernetes.io/load-balancer-attributes: idle_timeout.timeout_seconds=3600
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:REGION:ACCOUNT:certificate/XXXX
```

Keep `replicas: 1` and `strategy: Recreate`. The ALB stickiness limitation
above applies identically here; `target-type: ip` routes to pod IPs but
still cannot pin a session to a pod without a cookie.

Use IRSA for Secrets Manager access rather than node instance roles.

## Cost note

`--min-instances`-style always-on is mandatory here too: there is no
scale-to-zero option that preserves sessions. A single 1 vCPU / 2 GB
Fargate task running continuously is the floor. 
