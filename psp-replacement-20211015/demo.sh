#!/bin/bash

set -euo pipefail

########################
# include the magic
########################
. ../vendor/demo-magic/demo-magic.sh

# DEMO_CMD_COLOR=$BLACK
DEMO_COMMENT_COLOR=$DEMO_CMD_COLOR

if [[ -z ${TYPE_SPEED:-} ]]; then
    TYPE_SPEED=""
else
    TYPE_SPEED=40
fi

NAMESPACE=demo

(
    kubectl create namespace $NAMESPACE
    kubectl label namespace $NAMESPACE 'pod-security.kubernetes.io/enforce-version=v1.19'
) > /dev/null

clean_up() {
    ARG=$?
    kubectl delete namespace $NAMESPACE --force=true
    exit $ARG
}
trap clean_up EXIT

wait_ready() {
    kubectl wait --for=condition=Ready $1 > /dev/null
}

# hide the evidence
printf '%.0s\n' {1..50}
clear

# Setup
p "# minikube start --feature-gates='PodSecurity=true' --kubernetes-version=v1.22.1"
pe "kubectl config set-context --current --namespace=$NAMESPACE"

# Look how easy it is to take over the cluster if I can create a pod:
pe "cat privileged-pod.yaml" # Note privileged, hostPID
pe "kubectl create -f privileged-pod.yaml"
wait_ready pod/privileged-pod
# pe "kubectl exec privileged-pod -- cat /proc/1/cmdline" && echo
pe "kubectl exec privileged-pod -- cat /proc/1/root/var/lib/kubelet/pki/kubelet.key"
pe "kubectl delete -f privileged-pod.yaml --force"
# pe $'kubectl run privilege-pod --rm -it --privileged --image=alpine --overrides=\'{"spec":{"hostPID": true}}\''
pe "clear"

# Configure the namespace to enforce the baseline pod security level.
pe "kubectl label namespace $NAMESPACE 'pod-security.kubernetes.io/enforce=baseline'"
# > namespace/demo labeled

# And try it again:
pe "kubectl create -f privileged-pod.yaml" || true
# > Error from server (Failure): host namespaces (hostPID=true), privileged (container "privileged-pod" must not set securityContext.privileged=true)

# Now let's look at a "baseline" pod. Notice that this is the bare minimum specification for a pod - just a single container with an image.
pe "cat baseline-pod.yaml"
pe "kubectl create -f baseline-pod.yaml"
wait_ready pod/baseline-pod
# Of course this pod isn't running with HostPID or privileged, so the same attack no longer works.
# pe "kubectl exec baseline-pod -- cat /proc/1/cmdline" && echo
pe "kubectl exec baseline-pod -- cat /proc/1/root/var/lib/kubelet/pki/kubelet.key" || true
pe "kubectl delete -f baseline-pod.yaml --force"
pe "clear"

# What about the restricted level?
pe "kubectl label namespace $NAMESPACE pod-security.kubernetes.io/enforce=restricted --overwrite"
# > namespace/demo labeled

# And try the baseline pod again:
pe "kubectl create -f baseline-pod.yaml" || true
# > Error from server (Failure): allowPrivilegeEscalation != false (container "baseline-pod" must set securityContext.allowPrivilegeEscalation=false),
#   unrestricted capabilities (container "baseline-pod" must set securityContext.capabilities.drop=["ALL"]), runAsNonRoot != true (pod or container
#   "baseline-pod" must set securityContext.runAsNonRoot=true), seccompProfile (pod or container "baseline-pod" must set securityContext.seccompProfile.type to "Runtime$NAMESPACE" or "Localhost")

# Here is the "minimum viable restricted pod"
pe "cat restricted-pod.yaml"
pe "kubectl create -f restricted-pod.yaml"
wait_ready pod/restricted-pod
# Note that it's running as a non-root user.
pe "kubectl exec restricted-pod -- whoami" || true
# > whoami: unknown uid 1000
pe "kubectl delete -f restricted-pod.yaml --force"
pe "clear"

# Surprise! I cheated: demo was already labeled with enforce-version=v1.19. What happens if we remove that?
pe "kubectl describe namespace demo"
pe "kubectl label namespace $NAMESPACE 'pod-security.kubernetes.io/enforce-version'-"
pe "kubectl create -f restricted-pod.yaml" || true
# When the version label is omitted, the implied version is "latest".

# Let's go back to v1.19, and look at how we can make this transition safely.
pe "kubectl label namespace $NAMESPACE 'pod-security.kubernetes.io/enforce-version=v1.19'"
# Version is optional here.
pe "kubectl label namespace $NAMESPACE pod-security.kubernetes.io/warn=restricted"
pe "kubectl label namespace $NAMESPACE pod-security.kubernetes.io/warn-version=latest"
pe "kubectl create -f restricted-pod.yaml"
pe "clear"

# What about deployments? When you create a deployment, the deployment controller creates the pod, not the user.
# pe "cat restricted-deployment.yaml"
# pe "kubectl create -f restricted-deployment.yaml"
# PodSecurity works for any built-in types with an embedded pod template.

# One last thing - I didn't delete the pods this time. Let's see what happens if we update the enforce label again:
pe "kubectl get pods"
pe "kubectl label --dry-run=server namespace $NAMESPACE 'pod-security.kubernetes.io/enforce-version=latest' --overwrite"

p "# Fin!"
