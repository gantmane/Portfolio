// Terratest Test Suite for Terraform Modules
// Author: Evgeniy Gantman

package test

import (
	"testing"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestAwsVpcSecure(t *testing.T) {
	t.Parallel()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../aws-vpc-secure",
		Vars: map[string]interface{}{
			"vpc_name":           "test-vpc",
			"vpc_cidr":           "10.0.0.0/16",
			"availability_zones": []string{"us-east-1a", "us-east-1b"},
		},
	})

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	vpcID := terraform.Output(t, terraformOptions, "vpc_id")
	assert.NotEmpty(t, vpcID)
}

func TestAwsS3Secure(t *testing.T) {
	t.Parallel()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../aws-s3-secure",
		Vars: map[string]interface{}{
			"bucket_name":         "test-bucket-12345",
			"enable_versioning":   true,
			"enable_encryption":   true,
			"block_public_access": true,
		},
	})

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	bucketID := terraform.Output(t, terraformOptions, "bucket_id")
	assert.NotEmpty(t, bucketID)
}
