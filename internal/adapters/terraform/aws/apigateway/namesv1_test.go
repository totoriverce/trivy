package apigateway

import (
	"testing"

	v1 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v1"
	"github.com/aquasecurity/trivy-iac/test/testutil"
	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
)

func Test_adaptDomainNamesV1(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []v1.DomainName
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_api_gateway_domain_name" "example" {
}
`,
			expected: []v1.DomainName{
				{
					Name:           String(""),
					SecurityPolicy: String("TLS_1_0"),
				},
			},
		},
		{
			name: "basic",
			terraform: `
resource "aws_api_gateway_domain_name" "example" {
    domain_name = "testing.com"
    security_policy = "TLS_1_2"
}
`,
			expected: []v1.DomainName{
				{
					Name:           String("testing.com"),
					SecurityPolicy: String("TLS_1_2"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDomainNamesV1(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
