# VERSION defines the project version.
# Update this value when you upgrade the version of your project.
VERSION ?= 0.0.1

# Git and build information
REGISTRY ?= wireguard-operator
USERNAME ?= wireguard-operator
SHA ?= $(shell git describe --match=none --always --abbrev=8 --dirty)
TAG ?= $(shell if git describe --tags >/dev/null 2>&1; then git describe --tags --always --dirty; else echo "v0.0.0-$(SHA)"; fi)
BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)
# BUILD_TIME: Use git commit time if clean, current time if dirty
BUILD_TIME ?= $(shell if git diff --quiet HEAD >/dev/null 2>&1; then git log -1 --format=%cI; else date -u +%Y-%m-%dT%H:%M:%SZ; fi)
REGISTRY_AND_USERNAME := $(REGISTRY)/$(USERNAME)

# Set the Operator SDK version to use. By default, what is installed on the system is used.
# This is useful for CI or a project to utilize a specific version of the operator-sdk toolkit.
OPERATOR_SDK_VERSION ?= v1.41.1
# Image URL to use all building/pushing image targets
PREFIX_IMG_CONTROLLER ?= $(REGISTRY_AND_USERNAME)/wireguard-operator/controller
PREFIX_IMG_OPERATOR ?= $(REGISTRY_AND_USERNAME)/wireguard-operator/operator
IMG_CONTROLLER ?= $(PREFIX_IMG_CONTROLLER):$(TAG)
IMG_OPERATOR ?= $(PREFIX_IMG_OPERATOR):$(TAG)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	@echo "Generating CRDs to manifests/ directory..."
	@mkdir -p manifests
	$(CONTROLLER_GEN) crd paths="./..." output:crd:artifacts:config=manifests/
	@echo "CRDs generated successfully!"

.PHONY: helm-manifests
helm-manifests: manifests ## Copy and wrap CRDs for Helm chart.
	@echo "Creating consolidated crd.yaml for webhook generation..."
	@cat manifests/*.yaml > $(HELM_CHART_PATH)/crd.yaml
	@echo "CRDs wrapped successfully!"

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."
	go generate ./...

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

KIND_CLUSTER ?= wireguard-operator-test-e2e

.PHONY: setup-test-e2e
setup-test-e2e: ## Set up a Kind cluster for e2e tests if it does not exist
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@case "$$($(KIND) get clusters)" in \
		*"$(KIND_CLUSTER)"*) \
			echo "Kind cluster '$(KIND_CLUSTER)' already exists. Skipping creation." ;; \
		*) \
			echo "Creating Kind cluster '$(KIND_CLUSTER)'..."; \
			$(KIND) create cluster --name $(KIND_CLUSTER) ;; \
	esac

.PHONY: test-e2e
test-e2e: setup-test-e2e manifests generate fmt vet ## Run the e2e tests. Expected an isolated environment using Kind.
	KIND_CLUSTER=$(KIND_CLUSTER) go test ./test/e2e/ -v -ginkgo.v
	$(MAKE) cleanup-test-e2e

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## Tear down the Kind cluster used for e2e tests
	@$(KIND) delete cluster --name $(KIND_CLUSTER)

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	$(GOLANGCI_LINT) config verify

##@ Build


# Build flags
GO_BUILDFLAGS ?= -trimpath

GO_LDFLAGS ?= -s -w
GO_LDFLAGS += -X 'github.com/wireguard-operator/wireguard-operator/internal/version.Version=$(TAG)'
GO_LDFLAGS += -X 'github.com/wireguard-operator/wireguard-operator/internal/version.GitCommit=$(SHA)'
GO_LDFLAGS += -X 'github.com/wireguard-operator/wireguard-operator/internal/version.BuildTime=$(BUILD_TIME)'
GO_LDFLAGS += -X 'github.com/wireguard-operator/wireguard-operator/internal/version.GitBranch=$(BRANCH)'
GO_LDFLAGS += -X 'github.com/wireguard-operator/wireguard-operator/internal/config.DefaultOperatorImagePrefix=$(PREFIX_IMG_OPERATOR)'
GO_LDFLAGS += -X 'github.com/wireguard-operator/wireguard-operator/internal/config.DefaultControllerImagePrefix=$(PREFIX_IMG_CONTROLLER)'


BUILDX_ARGS := --build-arg REGISTRY_AND_USERNAME=$(REGISTRY_AND_USERNAME) \
               --build-arg NAME=wireguard-operator \
               --build-arg TAG=$(TAG) \
               --build-arg VERSION=$(TAG) \
               --build-arg GIT_COMMIT=$(SHA) \
               --build-arg BUILD_TIME="$(BUILD_TIME)" \
               --build-arg BRANCH=$(BRANCH) \
               --build-arg GO_BUILDFLAGS="$(GO_BUILDFLAGS)" \
               --build-arg GO_LDFLAGS="$(GO_LDFLAGS)"

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/amd64,linux/arm64

HELM_CHART_PATH ?= charts/wireguard-operator
HELM_NAMESPACE ?= wireguard-system

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -ldflags "$(GO_LDFLAGS)" -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run -ldflags "$(GO_LDFLAGS)" ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG_CONTROLLER} --target controller $(BUILDX_ARGS) .
	$(CONTAINER_TOOL) build -t ${IMG_OPERATOR} --target operator $(BUILDX_ARGS) .

.PHONY: kind-upload
kind-upload:
	@$(KIND) load docker-image ${IMG_CONTROLLER} --name $(KIND_CLUSTER)
	@$(KIND) load docker-image ${IMG_OPERATOR} --name $(KIND_CLUSTER)

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# Builder management
.PHONY: docker-setup-builder
docker-setup-builder:
	@if ! $(CONTAINER_TOOL) buildx ls | grep -q multibuilder; then \
		echo "Creating buildx builder..."; \
		$(CONTAINER_TOOL) buildx create --name multibuilder --driver docker-container --bootstrap; \
	fi
	$(CONTAINER_TOOL) buildx use multibuilder

PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	$(CONTAINER_TOOL) buildx create --name wireguard-operator-builder
	$(CONTAINER_TOOL) buildx use wireguard-operator-builder
	$(CONTAINER_TOOL) buildx build --tag ${IMG_CONTROLLER} --target controller $(BUILDX_ARGS) --push .
	$(CONTAINER_TOOL) buildx build --tag ${IMG_OPERATOR} --target operator $(BUILDX_ARGS) --push .
	$(CONTAINER_TOOL) buildx rm wireguard-operator-builder

.PHONY: build-installer
build-installer: helm manifests generate ## Generate a consolidated YAML with CRDs and deployment using Helm.
	mkdir -p dist
	$(HELM) template wireguard-operator $(HELM_CHART_PATH) \
		--set image.controller.repository=$(PREFIX_IMG_CONTROLLER) \
		--set image.controller.tag=$(TAG) \
		--set image.operator.repository=$(PREFIX_IMG_OPERATOR) \
		--set image.operator.tag=$(TAG) > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUBECTL) apply --server-side \
		-f manifests/wireguard-operator.io_wireguardpeers.yaml \
		-f manifests/wireguard-operator.io_wireguards.yaml \
		-f manifests/wireguard-operator.io_wireguardtrafficflows.yaml

.PHONY: uninstall
uninstall: helm ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
		$(HELM) delete wireguard-operator --namespace $(HELM_NAMESPACE)

FORCE_OWNERSHIP ?= false
.PHONY: deploy
deploy: helm helm-manifests ## Deploy controller to the K8s cluster specified in ~/.kube/config using Helm.
	$(HELM) upgrade --install wireguard-operator $(HELM_CHART_PATH) \
		$(if $(filter true,$(FORCE_OWNERSHIP)),--force --take-ownership) \
		--set image.controller.registry="" \
		--set image.controller.repository=$(PREFIX_IMG_CONTROLLER) \
		--set image.controller.tag=$(TAG) \
		--set image.operator.registry="" \
		--set image.operator.repository=$(PREFIX_IMG_OPERATOR) \
		--set image.operator.tag=$(TAG) \
		--set admissionWebhooks.certManager.enabled=true \
		--create-namespace \
		--namespace $(HELM_NAMESPACE) \
		--wait

.PHONY: undeploy
undeploy: helm ## Undeploy controller from the K8s cluster specified in ~/.kube/config using Helm. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(HELM) uninstall wireguard-operator --namespace $(HELM_NAMESPACE) --ignore-not-found || true

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUBECTL ?= kubectl
KIND ?= kind
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
HELM ?= $(LOCALBIN)/helm

## Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.18.0
#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell go list -m -f "{{ .Version }}" sigs.k8s.io/controller-runtime | awk -F'[v.]' '{printf "release-%d.%d", $$2, $$3}')
ENVTEST_K8S_VERSION ?= 1.30
#ENVTEST_K8S_VERSION ?= $(shell go list -m -f "{{ .Version }}" k8s.io/api | awk -F'[v.]' '{printf "1.%d", $$3}')
GOLANGCI_LINT_VERSION ?= v2.1.0
HELM_VERSION ?= v3.19.0
HELM_UNITTEST_VERSION ?= v1.0.3

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@$(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef

.PHONY: operator-sdk
OPERATOR_SDK ?= $(LOCALBIN)/operator-sdk
operator-sdk: ## Download operator-sdk locally if necessary.
ifeq (,$(wildcard $(OPERATOR_SDK)))
ifeq (, $(shell which operator-sdk 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPERATOR_SDK)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPERATOR_SDK) https://github.com/operator-framework/operator-sdk/releases/download/$(OPERATOR_SDK_VERSION)/operator-sdk_$${OS}_$${ARCH} ;\
	chmod +x $(OPERATOR_SDK) ;\
	}
else
OPERATOR_SDK = $(shell which operator-sdk)
endif
endif

.PHONY: helm
helm: $(HELM) ## Download helm locally if necessary.
$(HELM): $(LOCALBIN)
ifeq (,$(wildcard $(HELM)))
ifeq (, $(shell which helm 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(HELM)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSL https://get.helm.sh/helm-$(HELM_VERSION)-$${OS}-$${ARCH}.tar.gz | tar xz -C /tmp && \
	mv /tmp/$${OS}-$${ARCH}/helm $(HELM) && \
	rm -rf /tmp/$${OS}-$${ARCH} ;\
	chmod +x $(HELM) ;\
	}
else
HELM = $(shell which helm)
endif
endif

.PHONY: helm-unittest
helm-unittest: helm ## Install helm-unittest plugin if necessary.
	@$(HELM) plugin list | grep -q unittest || { \
		echo "Installing helm-unittest plugin $(HELM_UNITTEST_VERSION)..." ;\
		$(HELM) plugin install https://github.com/helm-unittest/helm-unittest.git --version $(HELM_UNITTEST_VERSION) ;\
	}

##@ Helm

.PHONY: helm-install
helm-install: helm helm-manifests ## Install the Helm chart
	$(HELM) install wireguard-operator $(HELM_CHART_PATH) \
		--set image.controller.repository=$(PREFIX_IMG_CONTROLLER) \
		--set image.controller.tag=$(TAG) \
		--set image.operator.repository=$(PREFIX_IMG_OPERATOR) \
		--set image.operator.tag=$(TAG) \
		--create-namespace \
		--namespace $(HELM_NAMESPACE)

.PHONY: helm-upgrade
helm-upgrade: helm helm-manifests ## Upgrade the Helm chart
	$(HELM) upgrade wireguard-operator $(HELM_CHART_PATH) \
		--set image.controller.repository=$(PREFIX_IMG_CONTROLLER) \
		--set image.controller.tag=$(TAG) \
		--set image.operator.repository=$(PREFIX_IMG_OPERATOR) \
		--set image.operator.tag=$(TAG) \
		--namespace $(HELM_NAMESPACE)

.PHONY: helm-uninstall
helm-uninstall: helm ## Uninstall the Helm chart
	$(HELM) uninstall wireguard-operator --namespace $(HELM_NAMESPACE) || true

.PHONY: helm-template
helm-template: helm helm-manifests ## Generate Kubernetes manifests from Helm chart
	$(HELM) template wireguard-operator $(HELM_CHART_PATH) \
		--set image.controller.repository=$(PREFIX_IMG_CONTROLLER) \
		--set image.controller.tag=$(TAG) \
		--set image.operator.repository=$(PREFIX_IMG_OPERATOR) \
		--set image.operator.tag=$(TAG)

.PHONY: helm-lint
helm-lint: helm ## Lint helm chart
	$(HELM) lint $(HELM_CHART_PATH)

.PHONY: helm-test
helm-test: helm-unittest helm-manifests ## Run helm chart unit tests
	$(HELM) unittest $(HELM_CHART_PATH)

.PHONY: helm-package
helm-package: helm helm-manifests ## Package helm chart
	$(HELM) package $(HELM_CHART_PATH) \
		--version $(TAG) \
		--app-version $(TAG)

.PHONY: helm-push
helm-push: helm-package
	@echo "Pushing Helm chart to OCI registry..."
	$(HELM) push wireguard-operator-$(TAG).tgz \
		oci://$(REGISTRY)/$(USERNAME)/charts

.PHONY: helm-release
helm-release: helm-manifests helm-lint helm-package helm-push

.PHONY: release
release: docker-buildx helm-release

.PHONY: deps-install-cert-manager
deps-install-cert-manager: helm
	$(HELM) install \
	  cert-manager oci://quay.io/jetstack/charts/cert-manager \
	  --version v1.18.2 \
	  --namespace cert-manager \
	  --create-namespace \
	  --set crds.enabled=true
