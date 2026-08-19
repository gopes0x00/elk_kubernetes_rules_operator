# Elastic Detection Rules Operator (`elastic-rules`)

`elastic-rules` is a Kubernetes operator built with `controller-runtime` and `kubebuilder` that manages Elastic Detection Engine Rules declaratively using Custom Resource Definitions (CRDs).

## Description

The `ElasticDetectionRule` CRD allows security engineers and cluster administrators to manage Elastic detection rules directly through Kubernetes manifests.

### Key Features
- **Lifecycle Management**: Automatically creates, updates, and deletes detection rules in Elastic Kibana via HTTP APIs.
- **Drift Detection & Auto-Recreation**: Periodically polls Elastic every minute to ensure rules exist and automatically recreates them if deleted out-of-band in Kibana.
- **Kubernetes Finalizers**: Ensures graceful rule deletion in Elastic when a Custom Resource (`ElasticDetectionRule`) is deleted from Kubernetes.
- **Status Tracking**: Updates CR `.status` with Elastic `ruleId`, `lastUpdated` timestamp, and `observedGeneration`.

---

## CRD Specification (`ElasticDetectionRule`)

```yaml
apiVersion: elasticdetectionrules.gopes0x00.internal/v1
kind: ElasticDetectionRule
metadata:
  name: k8s-pod-creation-audit
  namespace: elk
spec:
  name: "Kubernetes Pod Created via API Server Audit Logs"
  description: "Detects successful creation of a Kubernetes Pod in API server audit logs."
  type: "query" # Enum: query, eql, threshold, etc.
  query: 'verb: "create" and objectRef.resource: "pods" and responseStatus.code: 201 and stage: "ResponseComplete"'
  index:
    - "kubernetes-audit-*"
  severity: "medium" # Enum: low, medium, high, critical
  risk_score: 50
  enabled: true
```

---

## Getting Started

### Prerequisites
- Go version `v1.22+`
- Docker or Podman
- `kubectl` configured with cluster access
- Elastic / Kibana instance with Detection Engine API enabled

### Running Locally

1. **Install CRDs into your Kubernetes cluster:**
   ```sh
   make install
   ```

2. **Run the controller locally:**
   Pass your Elastic URL and credentials via CLI flags or Make arguments:
   ```sh
   make run ARGS="--elastic-url=http://192.168.1.92:30601 --elastic-username=api_rule_user --elastic-password=LetMeIn123"
   ```

3. **Apply a Sample Detection Rule:**
   ```sh
   kubectl apply -f config/samples/k8s_pod_creation_rule.yaml
   ```

---

## Command Line Flags

| Flag | Description | Default |
| --- | --- | --- |
| `--elastic-url` | The URL of the Elastic/Kibana server | `http://192.168.1.92:30601` |
| `--elastic-username` | Elastic authentication username | `api_rule_user` |
| `--elastic-password` | Elastic authentication password | `LetMeIn123` |
| `--metrics-bind-address` | Address for metrics endpoint (`0` to disable) | `0` |
| `--health-probe-bind-address` | Address for health probe | `:8081` |

---

## Deployment to Cluster

1. **Build and push container image:**
   ```sh
   make docker-build docker-push IMG=<your-registry>/elastic-rules-operator:v0.1.0
   ```

2. **Deploy to cluster:**
   ```sh
   make deploy IMG=<your-registry>/elastic-rules-operator:v0.1.0
   ```

---

## Cleanup

To remove installed resources from your cluster:

```sh
kubectl delete -f config/samples/k8s_pod_creation_rule.yaml
make uninstall
make undeploy
```

---

## License

Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
