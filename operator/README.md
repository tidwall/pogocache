# Pogocache Operator

A Kubernetes operator for managing [Pogocache](https://pogocache.com) instances via a `PogoCacheInstance` custom resource.

## Prerequisites

- Go 1.26+
- kubectl configured against your cluster
- controller-gen (for regenerating manifests): `go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.20.1`

## Installation

### One-line install (recommended)

Install the CRDs, RBAC, and operator Deployment in one command:

```sh
kubectl apply -f https://raw.githubusercontent.com/pogocache/pogocache/main/operator/config/install.yaml
```

Or from a local clone:

```sh
kubectl apply -f operator/config/install.yaml
```

### Install components separately

```sh
# CRD only
kubectl apply -f https://raw.githubusercontent.com/pogocache/pogocache/main/operator/config/crd/bases/cache.pogocache.io_pogocacheinstances.yaml

# RBAC (ServiceAccount, ClusterRole, ClusterRoleBinding)
kubectl apply -f https://raw.githubusercontent.com/pogocache/pogocache/main/operator/config/rbac/service_account.yaml
kubectl apply -f https://raw.githubusercontent.com/pogocache/pogocache/main/operator/config/rbac/role.yaml
kubectl apply -f https://raw.githubusercontent.com/pogocache/pogocache/main/operator/config/rbac/role_binding.yaml

# Operator Deployment
kubectl apply -f https://raw.githubusercontent.com/pogocache/pogocache/main/operator/config/manager/manager.yaml
```

### Uninstall

```sh
kubectl delete -f https://raw.githubusercontent.com/pogocache/pogocache/main/operator/config/install.yaml
```

## Quick start (from source)

```sh
# Install the CRD
make install

# Run the operator locally against the current kubeconfig context
make run

# In another terminal, apply the sample instance
make sample-apply

# Check status
kubectl get pogocacheinstances
```

## Custom Resource

```yaml
apiVersion: cache.pogocache.io/v1alpha1
kind: PogoCacheInstance
metadata:
  name: my-cache
spec:
  replicas: 1
  image: pogocache/pogocache:latest
  port: 9401
  threads: 4
  maxMemory: "512mb"
  evict: true
  maxConns: 1024
  resources:
    requests:
      cpu: "250m"
      memory: "256Mi"
    limits:
      cpu: "1000m"
      memory: "768Mi"
```

Short names: `kubectl get pci` or `kubectl get pogocache`

### Spec fields

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `replicas` | int32 | `1` | Number of pod replicas |
| `image` | string | `pogocache/pogocache:latest` | Container image |
| `port` | int32 | `9401` | Listening port |
| `threads` | int32 | CPU count | Worker thread count (`--threads`) |
| `maxMemory` | string | — | Memory limit e.g. `"80%"` or `"4gb"` (`--maxmemory`) |
| `evict` | bool | `true` | Evict keys at maxmemory (`--evict`) |
| `maxConns` | int32 | `1024` | Max concurrent connections (`--maxconns`) |
| `persist` | object | — | Persistence config (creates a PVC) |
| `auth` | object | — | Auth password (inline or Secret reference) |
| `tls` | object | — | TLS config (Secret reference) |
| `resources` | object | — | Pod resource requests/limits |
| `extraFlags` | string | — | Extra flags appended to `POGOCACHE_EXTRA_FLAGS` |
| `nodeSelector` | map | — | Node label selector |
| `tolerations` | array | — | Pod tolerations |
| `affinity` | object | — | Pod affinity rules |

### Persistence

```yaml
spec:
  persist:
    path: /data/pogocache.db
    size: 5Gi
    storageClassName: standard   # omit to use cluster default
```

Creates a PVC named `<name>-data` and mounts it at the specified path.

### Authentication

```yaml
# Option A: plaintext (dev only)
spec:
  auth:
    password: "changeme"

# Option B: Secret reference (recommended)
spec:
  auth:
    secretRef:
      name: pogocache-auth
      key: password
```

### TLS

Create a Secret with the required certificate files first:

```sh
kubectl create secret generic pogocache-tls \
  --from-file=tls.crt=pogocache.crt \
  --from-file=tls.key=pogocache.key \
  --from-file=ca.crt=ca.crt
```

Then reference it in the spec:

```yaml
spec:
  tls:
    port: 9402
    secretRef: pogocache-tls
```

## What the operator manages

For each `PogoCacheInstance` the operator creates and reconciles:

- **Deployment** — runs pogocache pods with the configured flags
- **Service** (ClusterIP) — exposes the cache port (and TLS port if configured)
- **PersistentVolumeClaim** — only when `spec.persist` is set

## Makefile targets

```sh
make build          # compile operator binary to ./bin/manager
make run            # run operator locally against current kubeconfig
make install        # install CRDs into cluster
make uninstall      # remove CRDs from cluster
make deploy         # install CRDs, RBAC, and operator Deployment
make undeploy       # remove all operator resources
make sample-apply   # apply the sample PogoCacheInstance
make sample-delete  # delete the sample PogoCacheInstance
make manifests          # regenerate CRD/RBAC YAML from Go markers
make generate-install   # rebuild config/install.yaml from component manifests
make generate       # regenerate DeepCopy implementations
make docker-build   # build operator container image
make docker-push    # push operator container image
```

## Deploying the operator to a cluster

```sh
# Build and push the operator image
make docker-build docker-push IMG=your-registry/pogocache-operator:latest

# Deploy everything (CRDs, RBAC, operator Deployment)
make deploy IMG=your-registry/pogocache-operator:latest

# Or apply the bundled manifest directly
kubectl apply -f config/install.yaml
```

The operator runs in the `pogocache-system` namespace.

## Status

```sh
kubectl get pogocacheinstances -o wide
# NAME               PHASE     READY   REPLICAS   AGE
# my-cache           Running   2       2          30s
```

Conditions: `Available`, `Progressing`, `Degraded` — following standard Kubernetes operator conventions.
