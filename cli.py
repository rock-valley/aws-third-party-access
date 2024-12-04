import json
import os
import argparse
from dotenv import load_dotenv
from jinja2 import Template
import boto3

load_dotenv()
TEMPLATE_DIR = "./templates"
OUTPUT_DIR = "./output"

iam_client = boto3.client("iam")
TAGS = [{"Key": "Vendor", "Value": "rvt"}]
role_names = {
    "console_access": os.getenv(
        "CONSOLE_ACCESS_ROLE_NAME", "RVTCrossAccountConsoleAccessRole"
    ),
    "api_access": os.getenv("API_ACCESS_ROLE_NAME", "RVTCrossAccountApiAccessRole"),
}


def load_templates(access_type):
    """Load all templates (trust and resource policies) for a given role."""
    role_template_dir = os.path.join(TEMPLATE_DIR, access_type)
    if not os.path.exists(role_template_dir):
        raise FileNotFoundError(
            f"Templates for role '{access_type}' not found in {TEMPLATE_DIR}."
        )

    templates = {}
    for file_name in os.listdir(role_template_dir):
        if file_name.endswith(".json"):
            template_path = os.path.join(role_template_dir, file_name)
            with open(template_path, "r", encoding="utf-8") as file:
                templates[file_name] = json.loads(file.read())

    return templates


def save_policy(access_type, policy_name, policy_data):
    """Save the policy to the output directory for a specific role."""
    role_output_dir = os.path.join(OUTPUT_DIR, access_type)
    os.makedirs(role_output_dir, exist_ok=True)
    output_path = os.path.join(role_output_dir, policy_name)
    with open(output_path, "w") as file:
        json.dump(policy_data, file, indent=4)
    print(f"Policy saved to {output_path}")


def process_templates(templates, variables):
    """Render templates using Jinja2 with given variables."""
    processed_policies = {}
    for name, policy_data in templates.items():
        policy_data_str = json.dumps(policy_data, indent=4)
        try:
            template = Template(policy_data_str)
            rendered_policy = template.render(variables[name])
            processed_policies[name] = json.loads(rendered_policy)
        except Exception as e:
            print(f"Error processing template {name}: {e}")
            raise

    return processed_policies


def create_role(access_type, trust_policy):
    """Create a role in AWS IAM."""
    role_name = role_names[access_type]
    print(f"Creating role: {role_name}")
    try:
        response = iam_client.create_role(
            RoleName=access_type,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=TAGS,
        )
        print(f"Role {access_type} created successfully with tags: {TAGS}")
        return response["Role"]["Arn"]
    except Exception as e:
        print(f"Failed to create role {access_type}: {e}")
        return None


def attach_policies(access_type, policy_arns):
    """Attach multiple policies to a role."""
    for policy_arn in policy_arns:
        try:
            iam_client.attach_role_policy(RoleName=access_type, PolicyArn=policy_arn)
            print(f"Policy {policy_arn} attached to role {access_type}.")
        except Exception as e:
            print(f"Failed to attach policy {policy_arn} to role {access_type}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Manage IAM roles and policies.")
    parser.add_argument(
        "--access-type",
        choices=["console_access", "api_access"],
        required=True,
        help="Access type for policies and role. (either console_access or api_access)",
    )
    parser.add_argument(
        "--action",
        choices=["create-policies", "create-role", "attach-policies"],
        required=True,
        help="Action to perform.",
    )
    parser.add_argument(
        "--policy-arns", nargs="+", help="List of ARNs to attach to the role."
    )

    args = parser.parse_args()

    # Load templates for the role
    templates = load_templates(args.access_type)
    variables = {
        "trust_policy_console_access.json": {
            "vendor_trust_principal_arn": os.getenv("VENDOR_TRUST_PRINCIPAL_ARN"),
        },
        "trust_policy_api_access.json": {
            "vendor_trust_principal_arn": os.getenv("VENDOR_TRUST_PRINCIPAL_ARN"),
            "aws_external_id": os.getenv("AWS_EXTERNAL_ID"),
        },
        "secrets-and-ssm.json": {
            "aws_region": os.getenv("AWS_REGION", "us-east-1"),
            "aws_account": os.getenv("AWS_ACCOUNT"),
            "secret_prefix": os.getenv("SECRET_PREFIX", "my-secret"),
            "ssm_prefix": os.getenv("SSM_PREFIX", "my-parameters"),
        },
        "tf-backend-usage.json": {
            "aws_account": os.getenv("AWS_ACCOUNT"),
            "dynamodb_table_name": os.getenv("DYNAMODB_TABLE_NAME", "terraform-lock"),
            "s3_bucket": os.getenv("S3_BUCKET", "terraform-backend-bucket"),
        },
    }

    if args.action == "create-policies":
        processed_policies = process_templates(templates, variables)
        for policy_name, policy_data in processed_policies.items():
            save_policy(args.access_type, policy_name, policy_data)
    elif args.action == "create-role":
        if f"trust_policy_{args.access_type}.json" not in templates:
            print(
                f"Error: trust_policy.json is required for role creation in {args.access_type}."
            )
            return
        trust_policy = process_templates(
            {
                f"trust_policy_{args.access_type}.json": templates[
                    f"trust_policy_{args.access_type}.json"
                ]
            },
            variables,
        )[f"trust_policy_{args.access_type}.json"]
        create_role(args.access_type, trust_policy)
    elif args.action == "attach-policies":
        if not args.policy_arns:
            print("Error: --policy-arns is required for attach-policies action.")
            return
        attach_policies(args.access_type, args.policy_arns)


if __name__ == "__main__":
    main()
