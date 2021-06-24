// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"os"

	"istio.io/istio/operator/cmd/mesh"
	binversion "istio.io/istio/operator/version"
	"istio.io/pkg/version"
)

//  Usage:
//  istioctl [command]
//
//  Available Commands:
//  analyze        Analyze Istio configuration and print validation messages
//  authz          (authz is experimental. Use `istioctl experimental authz`)
//  bug-report     Cluster information and log capture support tool.
//  dashboard      Access to Istio web UIs
//  experimental   Experimental commands that may be modified or deprecated
//  help           Help about any command
//  install        Applies an Istio manifest, installing or reconfiguring Istio on a cluster.
//  kube-inject    Inject Envoy sidecar into Kubernetes pod resources
//  manifest       Commands related to Istio manifests
//  operator       Commands related to Istio operator controller.
//  profile        Commands related to Istio configuration profiles
//  proxy-config   Retrieve information about proxy configuration from Envoy [kube only]
//  proxy-status   Retrieves the synchronization status of each Envoy in the mesh [kube only]
//  upgrade        Upgrade Istio control plane in-place
//  validate       Validate Istio policy and rules files
//  verify-install Verifies Istio Installation Status
//  version        Prints out build version information
//
//Flags:
//      --context string          The name of the kubeconfig context to use
//  -h, --help                    help for istioctl
//  -i, --istioNamespace string   Istio system namespace (default "istio-system")
//  -c, --kubeconfig string       Kubernetes configuration file
//  -n, --namespace string        Config namespace
//
//Additional help topics:
//  istioctl options        Displays istioctl global options

func main() {
	// 版本标识
	version.Info.Version = binversion.OperatorVersionString
	rootCmd := mesh.GetRootCmd(os.Args[1:])
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
