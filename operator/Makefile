# Makefile for the pogocache Kubernetes operator.
#
# Prerequisites:
#   - go 1.26+
#   - controller-gen  (go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.20.1)
#   - kubectl
#   - docker (or podman)

# Image name used by docker-build and deploy targets.
IMG ?= pogocache/pogocache-operator:latest

# Kubernetes namespace where the operator is deployed.
NAMESPACE ?= pogocache-system

# Path to controller-gen binary.  Prefer the module-local installation.
CONTROLLER_GEN ?= $(shell which controller-gen 2>/dev/null || echo "go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.20.1")

# All config directories applied by the deploy target.
CONFIG_DIRS := config/crd/bases config/rbac config/manager

.PHONY: all
all: build

##@ Development

.PHONY: fmt
fmt: ## Run goimports across all Go source files.
	goimports -w .

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: test
test: ## Run unit tests.
	go test -race -count=1 ./...

##@ Code generation

.PHONY: manifests
manifests: ## Generate CRD manifests and RBAC from kubebuilder markers.
	$(CONTROLLER_GEN) \
		rbac:roleName=pogocache-operator-manager-role \
		crd \
		webhook \
		paths="./..." \
		output:crd:artifacts:config=config/crd/bases \
		output:rbac:artifacts:config=config/rbac

.PHONY: generate
generate: ## Generate DeepCopy and other runtime.Object implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

##@ Build

.PHONY: build
build: ## Compile the operator binary to ./bin/manager.
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/manager ./main.go

.PHONY: run
run: ## Run the operator against the currently configured Kubernetes cluster.
	go run ./main.go

##@ Container image

.PHONY: docker-build
docker-build: ## Build the operator container image.
	docker build -t $(IMG) .

.PHONY: docker-push
docker-push: ## Push the operator container image.
	docker push $(IMG)

##@ Deployment

.PHONY: install
install: manifests ## Install CRDs into the currently configured cluster.
	kubectl apply -f config/crd/bases/

.PHONY: uninstall
uninstall: ## Remove CRDs from the currently configured cluster.
	kubectl delete --ignore-not-found -f config/crd/bases/

.PHONY: deploy
deploy: manifests ## Deploy the operator (namespace, RBAC, CRDs, Deployment) to the cluster.
	kubectl apply -f config/crd/bases/
	kubectl apply -f config/rbac/
	kubectl apply -f config/manager/

.PHONY: undeploy
undeploy: ## Remove all operator resources from the cluster.
	kubectl delete --ignore-not-found -f config/manager/
	kubectl delete --ignore-not-found -f config/rbac/
	kubectl delete --ignore-not-found -f config/crd/bases/

.PHONY: generate-install
generate-install: manifests ## Regenerate the bundled config/install.yaml from component manifests.
	cat config/crd/bases/cache.pogocache.io_pogocacheinstances.yaml \
	    config/rbac/service_account.yaml \
	    config/rbac/role.yaml \
	    config/rbac/role_binding.yaml \
	    config/manager/manager.yaml \
	    > config/install.yaml

##@ Samples

.PHONY: sample-apply
sample-apply: ## Apply the sample PogoCacheInstance to the cluster.
	kubectl apply -f config/samples/cache_v1alpha1_pogocache.yaml

.PHONY: sample-delete
sample-delete: ## Delete the sample PogoCacheInstance from the cluster.
	kubectl delete --ignore-not-found -f config/samples/cache_v1alpha1_pogocache.yaml

##@ Help

.PHONY: help
help: ## Display this help screen.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
