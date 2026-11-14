---
id: K8S-01
name: Kubernetes or EKS abuse - privileged or host-mounted pod, exec into a pod, cluster-admin binding, anonymous API access
category: cloud
status: todo
language: esql
index: logs-kubernetes.audit_logs-*
mitre: [T1610, T1611, T1609, T1078.001]
data_source: Kubernetes API server audit logs (EKS control-plane audit logging)
suppression:
  fields: [kubernetes.audit.user.username, finding]
  duration: 6h
  missing_fields: do_not_suppress
---

**Not collected in this estate yet, and off by default in EKS.** EKS writes API-server audit logs only when
control-plane logging is enabled for the `audit` log type. The logs then go to CloudWatch, and they must be shipped to
Elastic from there. Check both before building on this rule. Host-side container escapes are covered by `L08`, from
Falcon on the nodes.

Four shapes, each a single audit event, and each rare in a cluster run through CI/CD:

| `finding` | Signal | Why |
|---|---|---|
| `privileged_pod` | a pod created with `securityContext.privileged: true` | full access to the node's kernel and devices: the container-escape setup |
| `host_namespace_or_hostpath_pod` | `hostPID`, `hostNetwork` or `hostIPC`, or a `hostPath` volume | the node's processes, network or filesystem, reachable from the pod |
| `exec_into_pod` | `create` on the `pods/exec` or `pods/attach` subresource | an interactive shell in a running workload. CI/CD deploys and does not exec |
| `cluster_admin_binding` | a ClusterRoleBinding or RoleBinding to `cluster-admin` | escalation to full control of the cluster |
| `anonymous_api_call` | a request by `system:anonymous` that was allowed | a misconfigured API server answering unauthenticated callers |

## Query

Run every 5 minutes with a 10-minute lookback.

```esql
FROM logs-kubernetes.audit_logs-* METADATA _id, _index, _version
| WHERE kubernetes.audit.stage == "ResponseComplete"
  AND (kubernetes.audit.objectRef.resource IN ("pods", "clusterrolebindings", "rolebindings")
       OR kubernetes.audit.user.username == "system:anonymous")
| EVAL res = COALESCE(kubernetes.audit.objectRef.resource, ""),
       sub = COALESCE(kubernetes.audit.objectRef.subresource, ""),
       verb = COALESCE(kubernetes.audit.verb, ""),
       who = COALESCE(kubernetes.audit.user.username, ""),
       decision = COALESCE(`kubernetes.audit.annotations.authorization_k8s_io/decision`, ""),
       // pod-spec fields are multi-valued (one per container); flatten before testing
       privileged = COALESCE(MV_CONCAT(TO_STRING(kubernetes.audit.requestObject.spec.containers.securityContext.privileged), ","), "") LIKE "*true*",
       host_ns = COALESCE(MV_CONCAT(TO_STRING(kubernetes.audit.requestObject.spec.hostPID), ","), "") LIKE "*true*"
                 OR COALESCE(MV_CONCAT(TO_STRING(kubernetes.audit.requestObject.spec.hostNetwork), ","), "") LIKE "*true*"
                 OR COALESCE(MV_CONCAT(TO_STRING(kubernetes.audit.requestObject.spec.hostIPC), ","), "") LIKE "*true*",
       host_path = kubernetes.audit.requestObject.spec.volumes.hostPath.path IS NOT NULL,
       role = COALESCE(TO_STRING(kubernetes.audit.requestObject.roleRef.name), "")
| EVAL finding = CASE(
         res == "pods" AND sub IN ("exec", "attach") AND verb IN ("create", "get"), "exec_into_pod",
         res == "pods" AND sub == "" AND verb == "create" AND privileged, "privileged_pod",
         res == "pods" AND sub == "" AND verb == "create" AND (host_ns OR host_path), "host_namespace_or_hostpath_pod",
         res IN ("clusterrolebindings", "rolebindings") AND verb IN ("create", "update", "patch")
           AND role == "cluster-admin", "cluster_admin_binding",
         who == "system:anonymous" AND decision == "allow", "anonymous_api_call")
| WHERE finding IS NOT NULL
| KEEP @timestamp, finding, who, kubernetes.audit.user.groups, verb, res, sub, kubernetes.audit.objectRef.namespace,
       kubernetes.audit.objectRef.name, role, kubernetes.audit.sourceIPs, kubernetes.audit.userAgent,
       kubernetes.audit.responseStatus.code, _id, _version, _index
```

## Before turning it on

```esql
FROM logs-kubernetes.audit_logs-*
| WHERE @timestamp >= NOW() - 24 hours
| STATS events = COUNT(*), pod_creates = COUNT(*) WHERE kubernetes.audit.objectRef.resource == "pods"
    BY kubernetes.audit.verb
| SORT events DESC
```

- No rows means audit logs are not reaching Elastic.
- **System namespaces.** CNI plugins, CSI drivers, log shippers and the Falcon container sensor itself run
  privileged and with `hostPath`, in `kube-system` and similar namespaces. Exclude them as the pair of namespace and
  the service account that deploys them (the DaemonSet controller), never the namespace alone. A privileged pod
  created in `kube-system` by a **person** is still the case.
- **Break-glass exec.** Platform engineers do exec into pods during incidents. Exclude named SRE identities only if
  their exec is otherwise reviewed, and prefer a label over an exclusion.

## What it misses

- **Escalation through a role that is not literally `cluster-admin`**, such as a custom ClusterRole with `*` verbs on
  `*` resources. Extend `role` with your own high-privilege role names.
- **Secrets read through the API** (`get` on `secrets` across namespaces). It is a natural fifth branch once the
  service accounts that legitimately read secrets are known.
- **Workload-identity abuse**: a pod's IAM role (IRSA) used from outside the cluster. That shows in CloudTrail as the
  role being assumed from an unexpected source.

## When it fires

For a privileged or host-mounted pod: delete it, then check the node it was scheduled on for new processes (Falcon on
the node, `L08`). For a binding: remove it, then read everything the bound subject did. For anonymous access: fix the
API server's `--anonymous-auth` setting or the RBAC binding that grants `system:anonymous`.
