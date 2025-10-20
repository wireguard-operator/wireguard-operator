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

package utils

import (
	"fmt"
	"hash/fnv"

	"k8s.io/apimachinery/pkg/util/dump"
)

// DeepHashObject calculates a hash of any object using Kubernetes' dump.ForHash
// This provides a consistent way to detect changes in CRD resources
func DeepHashObject(obj interface{}) uint64 {
	hasher := fnv.New64a()
	hasher.Reset()
	if _, err := fmt.Fprintf(hasher, "%v", dump.ForHash(obj)); err != nil {
		// Hash function Write methods never return errors in practice,
		// but if it somehow does, we return 0 as an invalid hash
		return 0
	}
	return hasher.Sum64()
}
