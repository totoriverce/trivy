## trivy aws

[EXPERIMENTAL] Scan AWS account

### Synopsis

Scan an AWS account for misconfigurations. Trivy uses the same authentication methods as the AWS CLI. See https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html

The following services are supported:

- accessanalyzer
- api-gateway
- athena
- cloudfront
- cloudtrail
- cloudwatch
- codebuild
- documentdb
- dynamodb
- ec2
- ecr
- ecs
- efs
- eks
- elasticache
- elasticsearch
- elb
- emr
- iam
- kinesis
- kms
- lambda
- mq
- msk
- neptune
- rds
- redshift
- s3
- sns
- sqs
- ssm
- workspaces


```
trivy aws [flags]
```

### Examples

```
  # basic scanning
  $ trivy aws --region us-east-1

  # limit scan to a single service:
  $ trivy aws --region us-east-1 --service s3

  # limit scan to multiple services:
  $ trivy aws --region us-east-1 --service s3 --service ec2

  # force refresh of cache for fresh results
  $ trivy aws --region us-east-1 --update-cache

```

### Options

```
      --account string                    The AWS account to scan. It's useful to specify this when reviewing cached results for multiple accounts.
      --arn string                        The AWS ARN to show results for. Useful to filter results once a scan is cached.
      --cf-params strings                 specify paths to override the CloudFormation parameters files
      --check-namespaces strings          Rego namespaces
      --checks-bundle-repository string   OCI registry URL to retrieve checks bundle from (default "ghcr.io/aquasecurity/trivy-checks:0")
      --compliance string                 compliance report to generate (aws-cis-1.2,aws-cis-1.4)
      --config-check strings              specify the paths to the Rego check files or to the directories containing them, applying config files
      --config-data strings               specify paths from which data for the Rego checks will be recursively loaded
      --dependency-tree                   [EXPERIMENTAL] show dependency origin tree of vulnerable packages
      --endpoint string                   AWS Endpoint override
      --exit-code int                     specify exit code when any security issues are found
  -f, --format string                     format (table,json,template,sarif,cyclonedx,spdx,spdx-json,github,cosign-vuln) (default "table")
      --helm-api-versions strings         Available API versions used for Capabilities.APIVersions. This flag is the same as the api-versions flag of the helm template command. (can specify multiple or separate values with commas: policy/v1/PodDisruptionBudget,apps/v1/Deployment)
      --helm-kube-version string          Kubernetes version used for Capabilities.KubeVersion. This flag is the same as the kube-version flag of the helm template command.
      --helm-set strings                  specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-set-file strings             specify Helm values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)
      --helm-set-string strings           specify Helm string values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
      --helm-values strings               specify paths to override the Helm values.yaml files
  -h, --help                              help for aws
      --ignore-policy string              specify the Rego file path to evaluate each vulnerability
      --ignorefile string                 specify .trivyignore file (default ".trivyignore")
      --include-non-failures              include successes and exceptions, available with '--scanners misconfig'
      --list-all-pkgs                     enabling the option will output all packages regardless of vulnerability
      --max-cache-age duration            The maximum age of the cloud cache. Cached data will be required from the cloud provider if it is older than this. (default 24h0m0s)
      --misconfig-scanners strings        comma-separated list of misconfig scanners to use for misconfiguration scanning (default [azure-arm,cloudformation,dockerfile,helm,kubernetes,terraform,terraformplan-json,terraformplan-snapshot])
  -o, --output string                     output file name
      --output-plugin-arg string          [EXPERIMENTAL] output plugin arguments
      --region string                     AWS Region to scan
      --report string                     specify a report format for the output (all,summary) (default "all")
      --reset-checks-bundle               remove checks bundle
      --service strings                   Only scan AWS Service(s) specified with this flag. Can specify multiple services using --service A --service B etc.
  -s, --severity strings                  severities of security issues to be displayed (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL) (default [UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL])
      --skip-check-update                 skip fetching rego check updates
      --skip-service strings              Skip selected AWS Service(s) specified with this flag. Can specify multiple services using --skip-service A --skip-service B etc.
  -t, --template string                   output template
      --tf-exclude-downloaded-modules     exclude misconfigurations for downloaded terraform modules
      --tf-vars strings                   specify paths to override the Terraform tfvars files
      --trace                             enable more verbose trace output for custom queries
      --update-cache                      Update the cache for the applicable cloud provider instead of using cached results.
```

### Options inherited from parent commands

```
      --cache-dir string          cache directory (default "/path/to/cache")
  -c, --config string             config path (default "trivy.yaml")
  -d, --debug                     debug mode
      --generate-default-config   write the default config to trivy-default.yaml
      --insecure                  allow insecure server connections
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
  -v, --version                   show version
```

### SEE ALSO

* [trivy](trivy.md)	 - Unified security scanner

