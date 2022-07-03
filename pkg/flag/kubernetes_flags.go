package flag

import (
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	ClusterContextFlag = "context"
	NamespaceFlag      = "namespace"
	ReportFormatFlag   = "report"
)

type KubernetesFlags struct {
	ClusterContext *string
	Namespace      *string
	ReportFormat   *string
}

type KubernetesOptions struct {
	ClusterContext string
	Namespace      string
	ReportFormat   string
}

func NewKubernetesDefaultFlags() *KubernetesFlags {
	return &KubernetesFlags{
		ClusterContext: lo.ToPtr(""),
		Namespace:      lo.ToPtr(""),
		ReportFormat:   lo.ToPtr("all"),
	}
}

func (f *KubernetesFlags) AddFlags(cmd *cobra.Command) {
	if f.ClusterContext != nil {
		cmd.Flags().String(ClusterContextFlag, *f.ClusterContext, "specify a context to scan")
		viper.RegisterAlias(ClusterContextFlag, "ctx")
	}
	if f.Namespace != nil {
		cmd.Flags().StringP(NamespaceFlag, "n", *f.Namespace, "specify a namespace to scan")
	}
	if f.ReportFormat != nil {
		cmd.Flags().String(ReportFormatFlag, *f.ReportFormat, "specify a report format for the output. (all,summary)")
	}
}

func (f *KubernetesFlags) ToOptions() KubernetesOptions {
	return KubernetesOptions{
		ClusterContext: viper.GetString(ClusterContextFlag),
		Namespace:      viper.GetString(NamespaceFlag),
		ReportFormat:   viper.GetString(ReportFormatFlag),
	}
}
