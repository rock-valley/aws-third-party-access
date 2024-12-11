# AWS Third-Party Access
Scripts for managing AWS access for vendors, contractors, and other unsavory characters.


This library automates the creation and management of **cross-account roles** in AWS to securely grant vendors, contractors, or other third parties limited access to your account. The library creates roles for both **console access** and **API access**, ensuring security and compliance with AWS best practices.

## Features
- **Role Management**: Create, attach policies, and delete roles with ease.
- **Policy Management**: Define custom IAM policies using Jinja2 templates.
- **Tag Enforcement**: Enforce consistent tagging for roles and policies.
- **Dynamic Configuration**: Supports environment-based configurations via `.env`.

## Terminology
- **Target Account**: Your AWS account granting access.
- **Cross Account**: The third party's AWS account being granted access.

## Why Two Roles?
AWS requires separate roles for:
1. **Console Access**: For third parties using the AWS Management Console.
2. **API Access**: For programmatic access using `STS:AssumeRole` with `external-id`.

This wouldn't be required if the console supported `external-id`.

### How can I add more role types?
- create a role type (**e.g.,** `logger`); the value doesn't matter as long as it's unique in this repo.
- add to the `role_names` dictionary at the top of `cli.py`
- create a subfolder in `./templates` named after the role type

---

## Quick Start

### Prerequisites
1. **Python**: Install Python 3.8 or later.
2. **AWS CLI**: Ensure the AWS CLI is configured for your account.
3. **Environment Variables**: Create a `.env` file to store required configuration values.

---

### 1. Clone the Repository
```bash
git clone https://github.com/rock-valley/aws-third-party-access.git
cd aws-third-party-access
```

### 2. Install Dependencies
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure `.env`
Copy the example `.env` file:
```bash
cp .env.example .env
```
Update the `.env` file with your target account and cross-account details (see [Environment Variables](#environment-variables) for descriptions).

### 4. Define Policy Templates
- Add your policy templates in `./templates/<role_type>/` as `.json` files.
- Include a `trust_policy.json` file for each additional role.

---

## Usage

### Create Roles and Policies
1. **Validate Policies**:
   ```bash
   python ./cli.py --action create-statements
   ```
   This creates the policy statements in `./output` folder. Check the output for correctness before creating resources.

2. **Create All Resources**:
   ```bash
   python ./cli.py --action create
   ```
   This creates roles, attaches policies, and configures AWS resources.

3. **Create Specific Role**:
   ```bash
   python ./cli.py --action create --role-type <ROLE_TYPE>
   ```
4. **List Existing Roles and Policies**:
   ```bash
   python ./cli.py --action get-roles
   python ./cli.py --action get-policies
   ```
5. **Attach Policies**
   ```bash
   python ./cli.py --action attach-policies
   python ./cli.py --action attach-policies --role-type <ROLE_TYPE>
   ```

### Delete Roles and Policies
1. **Delete All Resources**:
   ```bash
   python ./cli.py --action delete
   ```
   This detaches policies and deletes the roles.

2. **Delete Specific Roles**:
   ```bash
   python ./cli.py --action delete-role --role-type <ROLE_TYPE>
   ```
---

## Environment Variables

These variables configure your AWS account and IAM role settings:

| Variable                       | Description                                                                                   |
|--------------------------------|-----------------------------------------------------------------------------------------------|
| `AWS_REGION`                   | AWS region of the target account.                                                            |
| `AWS_PROFILE`                  | AWS CLI profile to use for target account operations.                                        |
| `role_path`                    | Path prefix for roles (e.g., `/vendor/`). Optional but recommended for accounts with many roles. |
| `vendor_trust_principal_arn`   | ARN of the cross-account IAM entity that will assume the roles (provided by vendor).         |
| `vendor_tag_key`               | Tag key to enforce on roles and policies.                                                    |
| `vendor_tag_value`             | Tag value to enforce on roles and policies.                                                  |
| `project_prefix`               | Project namespace in resource names. Used to enforce on roles and policies.                  |
| `tf_backend_s3_bucket`         | Limit roles to specific S3 bucket (for TF backend)                                          |
| `tf_backend_dynamodb_table_name`| Limit roles to specific dynamo table (for TF backend)                                       |
| `CONSOLE_ACCESS_ROLE_NAME`     | Name of the role for console access.                                                         |
| `API_ACCESS_ROLE_NAME`         | Name of the role for API access.                                                             |
| `aws_external_id`              | External ID for cross-account role assumptions (provided by vendor).                        |


#### What if I need more variables for the additional policies I create?
Easy. Just add them to the `.env` file. The templating library will look in `os.environ` for variables. As long as it's there, you are good.

---

## How Third Parties Use These Roles

### Console Access
1. Log into their AWS account.
2. Navigate to:
   ```plaintext
   https://signin.aws.amazon.com/switchrole?roleName=<RoleName>&account=<AccountId>
   ```

### API Access
Add the following to their `~/.aws/config`:
```ini
[profile cross_account]
region = us-east-1
output = json
aws_access_key_id = example
aws_secret_access_key = example

[profile target_account]
region = us-east-1
output = json
role_arn = arn:aws:iam::TARGET_ACCOUNT_ID:role/ROLE_NAME
source_profile = cross_account
external_id = foo
role_session_name = bar
```

Then the cross account team can simple call `aws --profile target_account` or use `target_account` in terraform projects.

---
## Default Scenarios

### 1. Terraform Backend Restrictions
- Limit S3 and DynamoDB access for Terraform state files using:
  - `tf_backend_s3_bucket`
  - `tf_backend_dynamodb_table_name`

### 2. Secrets Manager and Parameter Store
- Limit access by prefix:
  - `ssm_prefix`
  - `secret_prefix`

---

### Resources
To better understand cross-account IAM roles, third-party access, and AWS security best practices, refer to the following resources:

1. [Securely Share Permissions with Third Parties - AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_share_securely_third_party.html)
2. [Cross-Account Resource Access - AWS IAM Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html)
3. [Using Roles with Third-Party Identity Providers - AWS IAM Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html)
4. [Securely Accessing Customer AWS Accounts with Cross-Account IAM Roles - AWS APN Blog](https://aws.amazon.com/blogs/apn/securely-accessing-customer-aws-accounts-with-cross-account-iam-roles/)
5. [Configuring your CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html )

