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
- add to the `role_names` dictionary at the top of `app/cli.py`
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

### 3. Setup
####  Configure `.env`
Copy the example `.env` file:
```bash
cp .env.example .env
```
Update the `.env` file with your target account and cross-account details (see [Environment Variables](#environment-variables) for descriptions).

#### Configure roles file and app/templates directory

1. **Add a `roles.json` File**:
   - Create a `roles.json` file in the `app` directory.
   - The structure should be as follows:
     ```json
     {
       "my_role_type": "my_role_name"
     }
     ```
   - The `role_type` can be any unique identifier; it just needs to be unique within this repository.

2. **Add Subfolders**:
   - For each role type defined in `roles.json`, create a subfolder in both:
     - `templates/pre/<ROLE_TYPE>`
     - `templates/post/<ROLE_TYPE>`

3. **Add a Trust Policy**:
   - Inside each `templates/post/<ROLE_TYPE>` folder, add a `trust_policy.json` file.
   - Refer to the `./examples` directory for example trust policy files.

### 4. Define Policy Templates

###$ Directory Structure
The `templates` directory has two main subfolders:

- **`pre`**: Contains YAML files that will be preprocessed by [policy_sentry](https://github.com/salesforce/policy_sentry). These YAML files define CRUD templates for IAM policies.
- **`post`**: Contains JSON files generated from the YAML CRUD templates in the `pre` folder. You can also add JSON files directly to the correct role folder in the `post` folder for additional customization (e.g., condition blocks, which policy_sentry doesn't handle).

Within both `pre` and `post` subfolders:
- There should be a subfolder for each role you are creating.
- Every role folder in the `templates/post` folder must include a `trust_policy.json` file to define the role's trust policy.

**Note:** Use cli to setup the role by running: `python app/cli.py --action init-role --role-type <ROLE_TYPE> --role-name <ROLE_NAME>`

#### Workflow for Policy Statements
1. **Create a CRUD Template**:
   Use the following command to create a `policy_sentry` CRUD template:
   ```bash
   python app/cli.py --action create-pre-template --role-type <ROLE_TYPE> --template-name <TEMPLATE_NAME>
   ```
   This will create a YAML template in the `templates/<ROLE_TYPE>/pre` folder.

2. **Define Resource ARNs**:
   Add the ARNs of resources in the CRUD template YAML file.

3. **Repeat or Add Custom JSON Templates**:
   - Repeat the process for additional CRUD templates as needed.
   - Alternatively, add JSON templates directly to the `templates/<ROLE_TYPE>/post` folder for customizations.

4. **Generate Policy Statements**:
   Run the following command to generate policy statements:
   ```bash
   python app/cli.py --action create-statements
   ```
   The generated policies will be in the `./output` directory.

5. **Review Policies**:
   Check the generated policies for accuracy before creating the roles and policies in AWS.

#### Notes
- Use the `pre` folder for YAML templates processed by `policy_sentry`.
- Use the `post` folder for JSON policies and additional customizations (e.g., condition blocks).
- Ensure every role folder in `templates/post` includes a `trust_policy.json`.

---

## Usage

The CLI tool provides several actions to manage IAM roles and policies. Below is a table of available actions, their descriptions, and example usage:

| **Action**            | **Description**                                                                                      | **Example**                                                                                           |
|------------------------|------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| `init-role`           | Initializes a new role by adding it to `app/roles.json`, creating required subfolders, and a trust policy file. **Requires `--role-type` and `--role-name`.** | `python app/cli.py --action init-role --role-name MyNewRole --role-type my_new_role_type`                |
| `create-pre-template` | Creates a `policy_sentry` CRUD template in the `templates/pre/<ROLE_TYPE>` directory. Requires `--template-name`. | `python app/cli.py --action create-pre-template --role-type my_role_type --template-name my_template`    |
| `process-pre-template`| Processes YAML templates from `templates/pre/<ROLE_TYPE>` to generate JSON files in `templates/post/<ROLE_TYPE>`. | `python app/cli.py --action process-pre-template --role-type my_role_type`                               |
| `create-statements`   | Combines templates and processes them into JSON statements in the `output` directory.                 | `python app/cli.py --action create-statements`                                                           |
| `create-policies`     | Creates IAM policies in AWS for the specified role type using generated templates.                   | `python app/cli.py --action create-policies`                                                             |
| `create-role`         | Creates an IAM role in AWS for the specified role type, attaching trust policies and other policies. | `python app/cli.py --action create-role`                                                                 |
| `attach-policies`     | Attaches existing policies to an IAM role in AWS.                                                   | `python app/cli.py --action attach-policies`                                                             |
| `get-policies`        | Retrieves all customer-managed policies from AWS.                                                   | `python app/cli.py --action get-policies`                                                               |
| `get-roles`           | Retrieves all IAM roles from AWS.                                                                    | `python app/cli.py --action get-roles`                                                                  |
| `delete-policies`     | Deletes policies associated with the specified role type.                                           | `python app/cli.py --action delete-policies`                                                             |
| `delete-role`         | Deletes the specified IAM role from AWS.                                                            | `python app/cli.py --action delete-role`                                                                 |
| `delete`              | Deletes both IAM policies and the role for the specified role type.                                 | `python app/cli.py --action delete`                                                                      |
| `create`              | Combines `create-statements`, `create-policies`, and `create-role` into a single workflow.          | `python app/cli.py --action create`                                                                      |

### Notes
- The `--role-type` argument is **required** for `init-role` and `create-pre-template`
- The `--role-name` argument is also required for `init-role`.
- For all other actions, if `--role-type` is **not provided**, the CLI will run the action for **all role types** defined in `roles.json`.
- Templates and policies are processed from the `templates/pre` and `templates/post` directories respectively.

### Recommendation
Use the following commands to make sure the statements look correct before using commands that change AWS:
- `init-role`
- `create-pre-template`
- `create-statements`

---

## Environment Variables

These variables configure your AWS account and IAM role settings:

| Variable                       | Description                                                                                   |
|--------------------------------|-----------------------------------------------------------------------------------------------|
| `AWS_REGION`                   | AWS region of the target account.                                                            |
| `AWS_PROFILE`                  | AWS CLI profile to use for target account operations.                                        |
| `role_path`                    | Path prefix for roles (e.g., `/vendor/`). Optional but recommended for accounts with many roles. |
| `vendor_trust_principal_arn`   | ARN of the cross-account IAM entity that will assume the roles (provided by vendor).         |
| `project_prefix`               | Project namespace in resource names. Used to enforce on roles and policies.                  |
| `vendor_tag_key`               | Tag name to apply to iam roles. Can be injected into policies as well                        |
| `vendor_tag_value`             | Tag value to apply to iam roles. Can be injected into policies as well                       |
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
- `project_prefix`
---

### Resources
To better understand cross-account IAM roles, third-party access, and AWS security best practices, refer to the following resources:

1. [Securely Share Permissions with Third Parties - AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_permissions_share_securely_third_party.html)
2. [Cross-Account Resource Access - AWS IAM Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html)
3. [Using Roles with Third-Party Identity Providers - AWS IAM Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html)
4. [Securely Accessing Customer AWS Accounts with Cross-Account IAM Roles - AWS APN Blog](https://aws.amazon.com/blogs/apn/securely-accessing-customer-aws-accounts-with-cross-account-iam-roles/)
5. [Configuring your CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html )
6. [Policy Sentry](https://github.com/salesforce/policy_sentry)
