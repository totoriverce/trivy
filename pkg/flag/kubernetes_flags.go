package flag

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
)

var (
	KubeConfigFlag = Flag[string]{
		Name:       "kubeconfig",
		ConfigName: "kubernetes.kubeconfig",
		Usage:      "specify the kubeconfig file path to use",
	}
	ComponentsFlag = Flag[[]string]{
		Name:       "components",
		ConfigName: "kubernetes.components",
		Default: []string{
			"workload",
			"infra",
		},
		Values: []string{
			"workload",
			"infra",
		},
		Usage: "specify which components to scan",
	}
	K8sVersionFlag = Flag[string]{
		Name:       "k8s-version",
		ConfigName: "kubernetes.k8s-version",
		Usage:      "specify k8s version to validate outdated api by it (example: 1.21.0)",
	}
	TolerationsFlag = Flag[[]string]{
		Name:       "tolerations",
		ConfigName: "kubernetes.tolerations",
		Usage:      "specify node-collector job tolerations (example: key1=value1:NoExecute,key2=value2:NoSchedule)",
	}
	NodeCollectorNamespace = Flag[string]{
		Name:       "node-collector-namespace",
		ConfigName: "kubernetes.node-collector.namespace",
		Default:    "trivy-temp",
		Usage:      "specify the namespace in which the node-collector job should be deployed",
	}
	NodeCollectorImageRef = Flag[string]{
		Name:       "node-collector-imageref",
		ConfigName: "kubernetes.node-collector.imageref",
		Default:    "ghcr.io/aquasecurity/node-collector:0.0.9",
		Usage:      "indicate the image reference for the node-collector scan job",
	}
	ExcludeOwned = Flag[bool]{
		Name:       "exclude-owned",
		ConfigName: "kubernetes.exclude.owned",
		Usage:      "exclude resources that have an owner reference",
	}
	ExcludeNodes = Flag[[]string]{
		Name:       "exclude-nodes",
		ConfigName: "kubernetes.exclude.nodes",
		Usage:      "indicate the node labels that the node-collector job should exclude from scanning (example: kubernetes.io/arch:arm64,team:dev)",
	}

	ExcludeKinds = Flag[[]string]{
		Name:       "exclude-kinds",
		ConfigName: "kubernetes.exclude.kinds",
		Usage:      "indicate the kinds exclude from scanning (example: node)",
	}
	IncludeKinds = Flag[[]string]{
		Name:       "include-kinds",
		ConfigName: "kubernetes.include.kinds",
		Usage:      "indicate the kinds included in scanning (example: node)",
	}
	ExcludeNamespaces = Flag[[]string]{
		Name:       "exclude-namespaces",
		ConfigName: "kubernetes.exclude.namespaces",
		Usage:      "indicate the namespaces excluded from scanning (example: kube-system)",
	}
	IncludeNamespaces = Flag[[]string]{
		Name:       "include-namespaces",
		ConfigName: "kubernetes.include.namespaces",
		Usage:      "indicate the namespaces included in scanning (example: kube-system)",
	}
	NodeCollectorImageRef = Flag[string]{
		Name:       "node-collector-imageref",
		ConfigName: "kubernetes.node.collector.imageref",
		Default:    "ghcr.io/aquasecurity/node-collector:0.0.9",
		Usage:      "indicate the image reference for the node-collector scan job",
	}
	QPS = Flag[float64]{
		Name:       "qps",
		ConfigName: "kubernetes.qps",
		Default:    5.0,
		Usage:      "specify the maximum QPS to the master from this client",
	}
	Burst = Flag[int]{
		Name:       "burst",
		ConfigName: "kubernetes.burst",
		Default:    10,
		Usage:      "specify the maximum burst for throttle",
	}
)

type K8sFlagGroup struct {
	KubeConfig             *Flag[string]
	Components             *Flag[[]string]
	K8sVersion             *Flag[string]
	Tolerations            *Flag[[]string]
	NodeCollectorImageRef  *Flag[string]
	NodeCollectorNamespace *Flag[string]
	ExcludeOwned           *Flag[bool]
	ExcludeNodes           *Flag[[]string]
	ExcludeKinds           *Flag[[]string]
	IncludeKinds           *Flag[[]string]
	ExcludeNamespaces      *Flag[[]string]
	IncludeNamespaces      *Flag[[]string]
	QPS                    *Flag[float64]
	Burst                  *Flag[int]
}

type K8sOptions struct {
	KubeConfig             string
	Components             []string
	K8sVersion             string
	Tolerations            []corev1.Toleration
	NodeCollectorImageRef  string
	NodeCollectorNamespace string
	ExcludeOwned           bool
	ExcludeNodes           map[string]string
	ExcludeKinds           []string
	IncludeKinds           []string
	ExcludeNamespaces      []string
	IncludeNamespaces      []string
	QPS                    float32
	Burst                  int
}

func NewK8sFlagGroup() *K8sFlagGroup {
	return &K8sFlagGroup{
		KubeConfig:             KubeConfigFlag.Clone(),
		Components:             ComponentsFlag.Clone(),
		K8sVersion:             K8sVersionFlag.Clone(),
		Tolerations:            TolerationsFlag.Clone(),
		NodeCollectorNamespace: NodeCollectorNamespace.Clone(),
		ExcludeOwned:           ExcludeOwned.Clone(),
		ExcludeNodes:           ExcludeNodes.Clone(),
		ExcludeKinds:           ExcludeKinds.Clone(),
		IncludeKinds:           IncludeKinds.Clone(),
		ExcludeNamespaces:      ExcludeNamespaces.Clone(),
		IncludeNamespaces:      IncludeNamespaces.Clone(),
		NodeCollectorImageRef:  NodeCollectorImageRef.Clone(),
		QPS:                    QPS.Clone(),
		Burst:                  Burst.Clone(),
	}
}

func (f *K8sFlagGroup) Name() string {
	return "Kubernetes"
}

func (f *K8sFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.KubeConfig,
		f.Components,
		f.K8sVersion,
		f.Tolerations,
		f.NodeCollectorNamespace,
		f.ExcludeOwned,
		f.ExcludeNodes,
		f.NodeCollectorImageRef,
		f.ExcludeKinds,
		f.IncludeKinds,
		f.ExcludeNamespaces,
		f.IncludeNamespaces,
		f.QPS,
		f.Burst,
	}
}

func (f *K8sFlagGroup) ToOptions() (K8sOptions, error) {
	if err := parseFlags(f); err != nil {
		return K8sOptions{}, err
	}

	tolerations, err := optionToTolerations(f.Tolerations.Value())
	if err != nil {
		return K8sOptions{}, err
	}

	exludeNodeLabels := make(map[string]string)
	exludeNodes := f.ExcludeNodes.Value()
	for _, exludeNodeValue := range exludeNodes {
		excludeNodeParts := strings.Split(exludeNodeValue, ":")
		if len(excludeNodeParts) != 2 {
			return K8sOptions{}, fmt.Errorf("exclude node %s must be a key:value", exludeNodeValue)
		}
		exludeNodeLabels[excludeNodeParts[0]] = excludeNodeParts[1]
	}
	if len(f.ExcludeNamespaces.Value()) > 0 && len(f.IncludeNamespaces.Value()) > 0 {
		return K8sOptions{}, fmt.Errorf("include-namespaces and exclude-namespaces flags cannot be used together")
	}
	if len(f.ExcludeKinds.Value()) > 0 && len(f.IncludeKinds.Value()) > 0 {
		return K8sOptions{}, fmt.Errorf("include-kinds and exclude-kinds flags cannot be used together")
	}

	return K8sOptions{
		KubeConfig:             f.KubeConfig.Value(),
		Components:             f.Components.Value(),
		K8sVersion:             f.K8sVersion.Value(),
		Tolerations:            tolerations,
		NodeCollectorNamespace: f.NodeCollectorNamespace.Value(),
		ExcludeOwned:           f.ExcludeOwned.Value(),
		ExcludeNodes:           exludeNodeLabels,
		NodeCollectorImageRef:  f.NodeCollectorImageRef.Value(),
		QPS:                    float32(f.QPS.Value()),
		ExcludeKinds:           f.ExcludeKinds.Value(),
		IncludeKinds:           f.IncludeKinds.Value(),
		ExcludeNamespaces:      f.ExcludeNamespaces.Value(),
		IncludeNamespaces:      f.IncludeNamespaces.Value(),
		Burst:                  f.Burst.Value(),
	}, nil
}

func optionToTolerations(tolerationsOptions []string) ([]corev1.Toleration, error) {
	var tolerations []corev1.Toleration
	for _, toleration := range tolerationsOptions {
		tolerationParts := strings.Split(toleration, ":")
		if len(tolerationParts) < 2 {
			return []corev1.Toleration{}, fmt.Errorf("toleration must include key and effect")
		}
		if corev1.TaintEffect(tolerationParts[1]) != corev1.TaintEffectNoSchedule &&
			corev1.TaintEffect(tolerationParts[1]) != corev1.TaintEffectPreferNoSchedule &&
			corev1.TaintEffect(tolerationParts[1]) != corev1.TaintEffectNoExecute {
			return []corev1.Toleration{}, fmt.Errorf("toleration effect must be a valid value")
		}
		keyValue := strings.Split(tolerationParts[0], "=")
		operator := corev1.TolerationOpEqual
		if keyValue[1] == "" {
			operator = corev1.TolerationOpExists
		}
		toleration := corev1.Toleration{
			Key:      keyValue[0],
			Value:    keyValue[1],
			Operator: operator,
			Effect:   corev1.TaintEffect(tolerationParts[1]),
		}
		var tolerationSec int
		var err error
		if len(tolerationParts) == 3 {
			tolerationSec, err = strconv.Atoi(tolerationParts[2])
			if err != nil {
				return nil, fmt.Errorf("TolerationSeconds must must be a number")
			}
			toleration.TolerationSeconds = lo.ToPtr(int64(tolerationSec))
		}
		tolerations = append(tolerations, toleration)
	}
	return tolerations, nil
}
