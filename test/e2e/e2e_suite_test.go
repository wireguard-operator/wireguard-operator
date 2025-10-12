/*
Copyright 2025 DenktMit eG and contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"fmt"
	"os/exec"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/wireguard-operator/wireguard-operator/test/utils"
)

var (
	// projectImage is the name of the image which will be build and loaded
	// with the code source changes to be tested.
	projectOperatorImage   = "local/wireguard-operator/operator"
	projectControllerImage = "local/wireguard-operator/controller"
	projectTag             = "v0.0.1-testing"
)

// TestE2E runs the end-to-end (e2e) test suite for the project. These tests execute in an isolated,
// temporary environment to validate project changes with the purposed to be used in CI jobs.
// The default setup requires Kind, builds/loads the Manager Docker image locally, and installs
// CertManager.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting wireguard-operator integration test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	By("building the manager(Operator) image")
	cmd := exec.Command(
		"make",
		"docker-build",
		fmt.Sprintf("TAG=%s", projectTag),
		fmt.Sprintf("PREFIX_IMG_CONTROLLER=%s", projectControllerImage),
		fmt.Sprintf("PREFIX_IMG_OPERATOR=%s", projectOperatorImage),
	)
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager(Operator) image")

	By("loading the manager(Operator) image on Kind")

	images := []string{
		fmt.Sprintf("%s:%s", projectOperatorImage, projectTag),
		fmt.Sprintf("%s:%s", projectControllerImage, projectTag),
	}

	for _, image := range images {
		err = utils.LoadImageToKindClusterWithName(image)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load the manager(Operator) image into Kind")
	}

	// The tests-e2e are intended to run on a temporary cluster that is created and destroyed for testing.
	// To prevent errors when tests run in environments with CertManager already installed,
	// we check for its presence before execution.
	// Setup CertManager before the suite if not skipped and if not already installed
	_, _ = fmt.Fprintf(GinkgoWriter, "Installing CertManager...\n")
	Expect(utils.InstallCertManager()).To(Succeed(), "Failed to install CertManager")
})
