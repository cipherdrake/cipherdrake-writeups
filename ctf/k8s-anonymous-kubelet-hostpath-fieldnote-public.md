---
title: "Field note: anonymous kubelet -> SA token -> create-pods = host root"
category: "field-note"
tags:
  - kubernetes
  - kubelet
  - anonymous-access
  - service-account-token
  - rbac
  - hostpath
  - container-escape
visibility: "public"
---

# Field note: anonymous kubelet -> SA token -> create-pods = host root

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

A single-node Kubernetes cluster shipped on defaults is a straight line from an unauthenticated network position to root on the node. No exploit code - every step uses the cluster's own primitives the way an over-permissive configuration allows. The recognition, not any tool, is the skill.

## The shape

Port-scan a k8s host and you see the control plane rather than a web app: the apiserver (6443/8443), the kubelet (10250), etcd (2379/2380), kube-proxy (10249/10256), plus SSH. Confirm the type from the apiserver's TLS cert (CN/organization naming Kubernetes/minikube, SANs like `kubernetes.default.svc.cluster.local`) and from its own error body - it will tell you `system:anonymous cannot get path "/"` if anonymous is refused there. The apiserver being locked does not matter, because the kubelet usually is not.

1. **The kubelet (10250) is the foothold when it accepts anonymous requests.** The kubelet is the per-node agent that runs pods. Misconfigured (anonymous auth on, authorization mode `AlwaysAllow`) it exposes:
   - `GET /pods` - lists every pod on the node.
   - `POST /run/<namespace>/<pod>/<container>` with `-d "cmd=..."` - **executes a command inside any container**, bypassing the apiserver's authentication entirely.
   Among the stock control-plane pods (etcd, apiserver, controller-manager, scheduler, kube-proxy, coredns, provisioner) look for the **one pod that does not belong** - a workload in the `default` namespace is something a person deployed, and it is the target.

2. **Every pod auto-mounts a service-account token; stealing it is one exec.** Kubernetes mounts a JWT at a fixed path inside each pod: `/var/run/secrets/kubernetes.io/serviceaccount/token`. Exec into the pod via the kubelet and read it. That token is a live credential for the apiserver - the same apiserver that refused you anonymously.

3. **Ask the apiserver what the token can do.** Point kubectl at it with the token and run `auth can-i --list`. You are hunting one permission above all: **`pods` with the verb `create`**. On a default cluster the `default` service account is often granted more than it should be.

4. **`create pods` is host root.** A pod's spec includes its volumes, and the kubelet runs pods as root on the node. So author a pod that **`hostPath`-mounts the node's `/` filesystem** into the container (`volumes: [{hostPath: {path: /}}]`, `mountPath: /mnt`). The node's entire filesystem - `/root`, `/home`, `/etc/shadow`, SSH keys - is now readable and writable from inside your pod. This is the Docker bind-mount host escape at the orchestration layer: the same trust boundary mounted straight through.

5. **The kubelet and apiserver are independent auth planes.** If the service account lacks `pods/exec` on the apiserver, you still exec into your new pod through the **anonymous kubelet** (`/run/<ns>/<newpod>/<container>`). Create with the apiserver token, exec with the kubelet.

## Two dead ends worth pre-empting

- **ImagePullBackOff on an air-gapped node.** `image: nginx` means `nginx:latest`, which is not cached and cannot be pulled with no internet. Read the exact image tag off an existing pod (`kubectl get pod <p> -o jsonpath='{.spec.containers[*].image}'`) and set that plus `imagePullPolicy: IfNotPresent` so the local image is used.
- **`create` but not `delete`/`patch`.** A minimal service account may be unable to fix or remove a broken pod. Do not mutate it - **create a new pod under a different name**. `create pods` alone is enough to own the node; you never need `delete`, `patch`, or apiserver `exec`.

## Recognition calls to keep

- **k8s control-plane ports + a minikube/Kubernetes cert = attack the cluster, not a web app.** The apiserver's own 403 body confirms whether anonymous is refused there.
- **Anonymous kubelet (10250) = exec into any pod on the node**, bypassing the apiserver. Always test `/pods` and `/run` first.
- **The odd pod (default namespace) is the planted target**; the rest is control-plane furniture.
- **Every pod carries an apiserver credential** at the service-account token path - one exec harvests it.
- **`create pods` = host root** via a `hostPath: /` pod; you do not need privileged, delete, patch, or apiserver exec.
- **Air-gapped node = use a locally cached image tag**, not `latest`.

## Why it matters (defensive)

- Disable anonymous kubelet auth (`--anonymous-auth=false`) and set kubelet authorization to `Webhook`, not `AlwaysAllow`. This one change removes the foothold.
- Do not auto-mount service-account tokens into workloads that do not need them (`automountServiceAccountToken: false`); give the default SA zero permissions.
- Least-privilege RBAC: the default service account must not be able to `create` pods.
- Enforce Pod Security admission (baseline/restricted) to forbid `hostPath` mounts and privileged pods.
- Firewall the control plane - the kubelet, etcd, and apiserver should never be reachable from untrusted networks.

The load-bearing lesson: in Kubernetes, "can create a pod" quietly means "can run root on the node," because a pod defines what it mounts and the kubelet runs it as root. Treat pod-create as a Tier-0 permission and close the anonymous kubelet, and the chain never starts.
