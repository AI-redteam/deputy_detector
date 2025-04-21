# AWS Confused Deputy Potential Vulnerability Detector

**Version:** 0.1.0
**Last Updated:** April 21, 2025

## Purpose

This Python tool is designed to assist AWS administrators, auditors, and security professionals in detecting potential policy misconfigurations that could lead to [Confused Deputy vulnerabilities](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html) within their AWS environment.

It performs **passive checks** on IAM trust policies and various resource-based policies, looking for common patterns associated with this vulnerability class.

**IMPORTANT:** This tool identifies *potential* risks based on policy analysis. Findings **require manual validation** within the context of your specific environment to determine actual exploitability and impact. This tool does **not** perform active exploitation.

## Features

* **Interactive Menu:** Easy-to-use menu for selecting checks and configuring output.
* **AWS Profile Selection:** Connects to your AWS account using named profiles from your `~/.aws/credentials` or `~/.aws/config` files.
* **Targeted Checks:** Performs specific checks for known confused deputy patterns across various AWS services.
* **Manual PoC Guidance:** Provides general steps on how to manually validate potential findings and demonstrate the associated risk (Proof of Concept).
* **Flexible Output:** Displays findings clearly in the console and offers an option to save detailed results to a JSON file.

## Checks Performed / Services Covered

The tool currently checks for the following potential misconfigurations:

1.  **IAM Roles:**
    * Checks role **Trust Policies** for principals belonging to external AWS accounts that are allowed `sts:AssumeRole` without a required `sts:ExternalId` condition.
2.  **S3 Buckets:**
    * Checks **Bucket Policies** for statements allowing AWS `Service` principals actions (e.g., `s3:PutObject`, `s3:GetObject`) without `aws:SourceAccount` or `aws:SourceArn` conditions.
3.  **SQS Queues:**
    * Checks **Queue Policies** for statements allowing AWS `Service` principals actions (e.g., `sqs:SendMessage`) without `aws:SourceAccount` or `aws:SourceArn` conditions.
4.  **SNS Topics:**
    * Checks **Topic Policies** for statements allowing AWS `Service` principals actions (e.g., `sns:Publish`) without `aws:SourceAccount` or `aws:SourceArn` conditions.
5.  **KMS Keys:**
    * Checks **Key Policies** (for Customer Managed Keys) for statements allowing AWS `Service` principals actions (e.g., cryptographic operations) without `aws:SourceAccount` or `aws:SourceArn` conditions.
6.  **Lambda Functions:**
    * Checks **Resource-Based Policies** (for function invocation) for statements allowing AWS `Service` principals the `lambda:InvokeFunction` action without `aws:SourceAccount` or `aws:SourceArn` conditions.
7.  **Secrets Manager Secrets:**
    * Checks **Resource-Based Policies** for statements allowing AWS `Service` principals the `secretsmanager:GetSecretValue` action without `aws:SourceAccount` or `aws:SourceArn` conditions.

## Future Enhancements

We plan to add checks for additional AWS services where resource policies or cross-service interactions are relevant to the Confused Deputy problem, such as:

* ECR Repositories (Repository Policies)
* Glue Data Catalog / Resources (Resource Policies)
* EventBridge Event Buses (Resource Policies)
* API Gateway (Resource Policies)
* *And others as needed.*

## Prerequisites

* **Python 3:** Tested with Python 3.6+.
* **Boto3:** AWS SDK for Python (`pip install boto3`).
* **AWS Credentials:** Configured AWS credentials with sufficient permissions (e.g., via `~/.aws/credentials`, `~/.aws/config`, environment variables, or an EC2 instance profile/ECS task role).

## Required IAM Permissions

The AWS principal (user or role) running this tool requires *at least* the following IAM permissions in the target account:

* `sts:GetCallerIdentity` (To identify the current account)
* `iam:ListRoles`
* `iam:GetRole` (Needed if AssumeRolePolicyDocument isn't included in ListRoles output)
* `s3:ListAllMyBuckets`
* `s3:GetBucketPolicy`
* `sqs:ListQueues`
* `sqs:GetQueueAttributes` (specifically requesting 'Policy' and 'QueueArn' attributes)
* `sns:ListTopics`
* `sns:GetTopicAttributes`
* `kms:ListKeys`
* `kms:DescribeKey` (To identify Customer Managed Keys)
* `kms:GetKeyPolicy`
* `lambda:ListFunctions`
* `lambda:GetPolicy`
* `secretsmanager:ListSecrets`
* `secretsmanager:GetResourcePolicy`

**Note:** The tool attempts to handle `AccessDenied` errors gracefully for individual services if permissions are missing, but core functionality like profile validation requires `sts:GetCallerIdentity`.

## How to Use

1.  **Save:** Save the complete Python script to a file (e.g., `aws_confused_deputy_check.py`).
2.  **Permissions:** Ensure the AWS profile you intend to use has the required IAM permissions listed above.
3.  **Run:** Execute the script from your terminal:
    ```bash
    python aws_confused_deputy_check.py
    ```
4.  **Select Profile:** Choose the desired AWS profile from the displayed list.
5.  **Select Checks:** Choose which service(s) to check from the main menu, or run all checks.
6.  **Configure Output (Optional):** Use the menu option to keep console-only output or enable saving results to a JSON file (you can customize the filename).
7.  **Review Results:** Examine the console output for potential findings and the corresponding manual PoC guidance. If file output is enabled, review the generated JSON file.

## Output

* **Console:** Findings are printed to the console, including the finding type, affected resource ARN, details of the misconfiguration, and detailed steps for manual PoC validation. Errors during checks are logged.
* **JSON File (Optional):** If enabled, a JSON file is created containing a list of finding objects. Each object includes:
    * `type`: The type of finding (e.g., "IAM Role Trust - Missing ExternalId").
    * `resource_arn`: The ARN of the affected resource.
    * `details`: A description of the potential issue.
    * `service_principal` / `trusted_principal`: The relevant principal involved.
    * `policy_statement`: The specific policy statement flagged.
    * `poc_guidance`: The multi-line string containing manual PoC steps.

## Disclaimer

This tool is provided for informational and auditing purposes only. The detection logic is based on common patterns and may produce false positives or miss context-specific nuances. **All findings must be manually verified by qualified personnel.** Do not rely solely on this tool for security assessments. The authors are not responsible for any misuse of this tool or misinterpretation of its results. This is **not** an exploitation tool.

---
*This README was generated based on tool requirements specified on April 21, 2025, in Georgetown, Texas, United States.*
