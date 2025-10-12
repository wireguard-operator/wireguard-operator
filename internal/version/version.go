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

package version

import (
	"fmt"
	"runtime"
)

// These variables are set via ldflags during build time
var (
	// Version is the semantic version of the application
	Version = "v0.0.0-dev"

	// GitCommit is the git commit SHA
	GitCommit = "unknown"

	// GitBranch is the git branch name
	GitBranch = "unknown"

	// BuildTime is the time the binary was built
	BuildTime = "unknown"

	// Platform is the platform the binary was built for
	Platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
)

// Info contains version information
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"gitCommit"`
	GitBranch string `json:"gitBranch"`
	BuildTime string `json:"buildTime"`
	Platform  string `json:"platform"`
	GoVersion string `json:"goVersion"`
}

// Get returns the version information
func Get() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		GitBranch: GitBranch,
		BuildTime: BuildTime,
		Platform:  Platform,
		GoVersion: runtime.Version(),
	}
}

// String returns a formatted version string
func (i Info) String() string {
	return fmt.Sprintf(
		"Version: %s\nGit Commit: %s\nGit Branch: %s\nBuild Time: %s\nPlatform: %s\nGo Version: %s",
		i.Version, i.GitCommit, i.GitBranch, i.BuildTime, i.Platform, i.GoVersion,
	)
}

// Short returns a short version string
func (i Info) Short() string {
	return fmt.Sprintf("%s (%s)", i.Version, i.GitCommit)
}
