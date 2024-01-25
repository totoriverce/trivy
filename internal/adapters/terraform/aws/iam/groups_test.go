package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"

	"github.com/aquasecurity/trivy-iac/test/testutil"
	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
)

func Test_adaptGroups(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []iam.Group
	}{
		{
			name: "policy",
			terraform: `
			resource "aws_iam_group_policy" "my_developer_policy" {
				name  = "my_developer_policy"
				group = aws_iam_group.my_developers.name

				policy = <<EOF
				{
				  "Version": "2012-10-17",
				  "Statement": [
				  {
					"Effect": "Allow",
					"Resource": "*",
					"Action": [
						"ec2:Describe*"
					]
				  }
				  ]
				}
				EOF
			  }
			  
			  resource "aws_iam_group" "my_developers" {
				name = "developers"
				path = "/users/"
			  }
			  
			  `,
			expected: []iam.Group{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					Name:     defsecTypes.String("developers", defsecTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: defsecTypes.NewTestMetadata(),
							Name:     defsecTypes.String("my_developer_policy", defsecTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(false),
						},
					},
				},
			},
		},
		{
			name: "attachment policy",
			terraform: `
resource "aws_iam_group" "group" {
  name = "test-group"
}

resource "aws_iam_policy" "policy" {
  name        = "test-policy"
  description = "A test policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_group_policy_attachment" "test-attach" {
  group      = aws_iam_group.group.name
  policy_arn = aws_iam_policy.policy.arn
}
`,
			expected: []iam.Group{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					Name:     defsecTypes.String("test-group", defsecTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: defsecTypes.NewTestMetadata(),
							Name:     defsecTypes.String("test-policy", defsecTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(false),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptGroups(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
