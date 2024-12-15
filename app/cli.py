import json
import os
import argparse
import shutil
from dotenv import load_dotenv
from resource_permissions import create_ps_template, create_policy_from_ps_template
from jinja2 import StrictUndefined, Environment
import boto3

load_dotenv()
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
iam_client = boto3.client("iam")


TEMPLATE_DIR = f"{current_dir}/templates"
OUTPUT_DIR = f"{root_dir}/output"
role_names = {}
TAGS = [{"Key": os.getenv("vendor_tag_key"), "Value": os.getenv("vendor_tag_value")}]
role_path = os.getenv("role_path", "/")

roles_file_path = f"{current_dir}/roles.json"

role_names = {}
if not role_path.startswith("/"):
    role_path = "/" + role_path
if not role_path.endswith("/"):
    role_path = role_path + "/"


def check_roles_file():
    global roles_file_path
    global role_names
    if not os.path.exists(roles_file_path):
        args = argparse.Namespace(template_name="roles.json")
        copy_example("", args)
        print(f"Copied example roles.json file to app/")

    with open(roles_file_path, "r") as roles_file:
        role_names = json.load(roles_file)
    for d in ["pre", "post"]:
        folder = os.path.join(TEMPLATE_DIR, d)
        os.makedirs(folder, exist_ok=True)
        subfolder_names = {
            name
            for name in os.listdir(folder)
            if os.path.isdir(os.path.join(folder, name))
        }
        for role_name in role_names:
            role_folder = os.path.join(folder, role_name)
            if role_name not in subfolder_names:
                os.makedirs(role_folder, exist_ok=True)
                print(f"Created missing folder: {role_folder}")

        subfolder_names = {
            name
            for name in os.listdir(folder)
            if os.path.isdir(os.path.join(folder, name))
        }
        if subfolder_names != set(role_names):
            raise FileNotFoundError(
                f"Subfolder mismatch in '{folder}'. Expected: {set(role_names)}, Found: {subfolder_names}"
            )


def setup_defaults():
    keys = role_names.keys()
    if "console_access" not in keys or "api_access" not in keys:
        print(f"Role names: {list(keys)} different than default names. Skipping setup")
        return
    defaults = [
        {
            "role_type": "api_access",
            "template_name": "trust_policy_with_external_id.json",
            "destination_name": "trust_policy.json",
        },
        {"role_type": "console_access", "template_name": "trust_policy.json"},
        {
            "role_type": "api_access",
            "template_name": "tf-backend-admin.yaml",
        },
        {
            "role_type": "console_access",
            "template_name": "tf-backend-usage.yaml",
        },
        {
            "role_type": "api_access",
            "template_name": "ssm-secrets-write.yaml",
        },
        {
            "role_type": "console_access",
            "template_name": "ssm-secrets-read.yaml",
        },
        {
            "role_type": "api_access",
            "template_name": "log-admin.yaml",
        },
        {
            "role_type": "console_access",
            "template_name": "log-read.yaml",
        },
    ]

    for default in defaults:
        try:
            args = argparse.Namespace(
                template_name=default["template_name"],
                destination_name=default.get("destination_name"),
            )
            copy_example(default["role_type"], args)
        except ValueError as e:
            print(
                f"Error for {default['role_type']} with {default['template_name']}: {e}"
            )


def copy_example(role_type, args):
    """
    Copies an example template file to the appropriate role_type directory if conditions are met.

    Args:
        role_type (str): The role type, used to locate the destination folder.
        args (Namespace): Arguments object with a `template_name` attribute.

    Raises:
        ValueError: If any of the checks fail.
    """
    if not hasattr(args, "template_name") or not args.template_name:
        raise ValueError("`template_name` is not defined in the provided arguments.")
    if not os.path.splitext(args.template_name)[1]:
        raise ValueError(
            "`template_name` must include a file extension (e.g., .yaml, .json)."
        )

    template_extension = os.path.splitext(args.template_name)[1].lower()

    if template_extension == ".json":
        role_type_dir = os.path.join(current_dir, "templates/post", role_type)
        if args.template_name == "roles.json":
            role_type_dir = current_dir
    elif template_extension in [".yml", ".yaml"]:
        role_type_dir = os.path.join(current_dir, "templates/pre", role_type)
    else:
        raise ValueError(
            f"Unsupported template extension '{template_extension}'. Only .json, .yml, or .yaml are allowed."
        )

    source_file = os.path.join(f"{root_dir}/examples", args.template_name)
    if not os.path.exists(role_type_dir):
        raise ValueError(f"The folder './templates/pre/{role_type}' does not exist.")

    if not os.path.exists(source_file):
        raise ValueError(
            f"Template file '{args.template_name}' does not exist in 'examples/'."
        )
    if not hasattr(args, "destination_name") or not args.destination_name:
        dest_name = os.path.basename(source_file)
    else:
        dest_name = args.destination_name
    destination_file = os.path.join(role_type_dir, dest_name)
    shutil.copy(source_file, destination_file)
    print(f"File '{source_file}' successfully copied to '{destination_file}'.")


def initialize_role(role_type, args):
    pre_folder = os.path.join(TEMPLATE_DIR, "pre", role_type)
    post_folder = os.path.join(TEMPLATE_DIR, "post", role_type)
    trust_policy_path = os.path.join(post_folder, "trust_policy.json")
    with open(roles_file_path, "r") as file:
        roles = json.load(file)
    if role_type in roles:
        raise ValueError(f"Role type '{role_type}' already exists in roles.json.")
    roles[role_type] = args.role_name

    with open(roles_file_path, "w") as file:
        json.dump(roles, file, indent=4)
    print(f"Added role '{role_type}' with name '{args.role_name}' to roles.json.")

    os.makedirs(pre_folder, exist_ok=True)
    os.makedirs(post_folder, exist_ok=True)
    print(f"Created subfolders for role '{role_type}' in 'pre' and 'post'.")

    if not os.path.exists(trust_policy_path):
        with open(trust_policy_path, "w") as file:
            json.dump({}, file)  # Empty JSON object
        print(f"Created empty trust_policy.json file at {trust_policy_path}.")


def create_policy_sentry_template(role_type, args):
    if not args.template_name:
        raise AttributeError("template_name arg is required")
    if not role_type:
        raise AttributeError("role_type arg is required")
    directory = os.path.join(TEMPLATE_DIR, "pre", role_type)
    create_ps_template(directory, args.template_name)


def process_pre_templates(role_type, args):
    pre_template_dir = os.path.join(TEMPLATE_DIR, "pre", role_type)
    post_template_dir = os.path.join(TEMPLATE_DIR, "post", role_type)
    for file_name in os.listdir(pre_template_dir):
        if file_name.endswith(".yaml") or file_name.endswith("yml"):
            create_policy_from_ps_template(
                pre_template_dir, post_template_dir, file_name
            )


def load_templates(role_type):
    """Load all templates (trust and resource policies) for a given role."""
    role_template_dir = os.path.join(TEMPLATE_DIR, "post", role_type)
    if not os.path.exists(role_template_dir):
        raise FileNotFoundError(
            f"Templates for role '{role_type}' not found in {TEMPLATE_DIR}/post."
        )

    templates = {}
    for file_name in os.listdir(role_template_dir):
        if file_name.endswith(".json"):
            template_path = os.path.join(role_template_dir, file_name)
            with open(template_path, "r", encoding="utf-8") as file:
                templates[file_name] = json.loads(file.read())

    return templates


def process_templates(templates):
    """Render templates using Jinja2 with environment variables."""
    env = Environment(undefined=StrictUndefined)
    processed_policies = {}
    for name, policy_content in templates.items():
        try:
            if isinstance(policy_content, dict):
                policy_content = json.dumps(policy_content, indent=4)
            template = env.from_string(policy_content)
            rendered_policy = template.render(os.environ)
            processed_policies[name] = json.loads(rendered_policy)
        except Exception as e:
            print(f"Error processing template {name}: {e}")
            raise

    return processed_policies


def get_role_name_by_access_type(role_type):
    return role_names[role_type]


def create_role(role_type, trust_policy):
    """Create a role in AWS IAM."""
    role_name = get_role_name_by_access_type(role_type)
    print(f"Creating role: {role_name}")
    try:
        response = iam_client.create_role(
            Path=role_path,
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=TAGS,
        )
        print(f"Role {role_type} created successfully with tags: {TAGS}")
        return response["Role"]["Arn"]
    except Exception as e:
        print(f"Failed to create role {role_type}: {e}")
        return None


def save_policy(role_type, policy_name, policy_data):
    """Save the policy to the output directory for a specific role."""
    role_output_dir = os.path.join(OUTPUT_DIR, role_type)
    os.makedirs(role_output_dir, exist_ok=True)
    output_path = os.path.join(role_output_dir, f"{role_type}-{policy_name}")
    with open(output_path, "w") as file:
        json.dump(policy_data, file, indent=4)
    print(f"Policy saved to {output_path}")


def create_policy(policy_data, file_name):
    """Create an IAM policy in AWS with a name derived from the filename."""
    policy_name = get_resource_name_from_filename(file_name)

    print(f"Creating policy: {policy_name}")
    try:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_data),
            Tags=TAGS,
        )
        print(f"Policy {policy_name} created successfully.")
        return response["Policy"]["Arn"]
    except Exception as e:
        print(f"Failed to create policy {policy_name}: {e}")
        return None


def attach_policies(role_type, policy_arns):
    """Attach multiple policies to a role."""
    for policy_arn in policy_arns:
        try:
            iam_client.attach_role_policy(RoleName=role_type, PolicyArn=policy_arn)
            print(f"Policy {policy_arn} attached to role {role_type}.")
        except Exception as e:
            print(f"Failed to attach policy {policy_arn} to role {role_type}: {e}")


def resource_exists(resource_name, list_function, name_key, tag_function=None):
    """
    Generic function to check if a resource exists by name and matches required tags.

    Args:
        resource_name (str): Name of the resource to check.
        list_function (callable): Function to list resources (e.g., list_policies, list_roles).
        name_key (str): Key in the resource dict where the name is stored.
        tag_function (callable, optional): Function to list tags for a resource.

    Returns:
        str: Resource ARN if it exists and matches tags; otherwise None.
    """
    try:
        paginator = list_function()
        for page in paginator.paginate():
            for resource in page.get("Policies", []) + page.get("Roles", []):
                if resource[name_key] == resource_name:
                    if tag_function:
                        arn = resource["Arn"]
                        tags = tag_function(arn)["Tags"]
                        if all(tag in tags for tag in TAGS):
                            return arn
                    else:
                        return resource["Arn"]
        return None
    except Exception as e:
        print(f"Error checking resource existence: {e}")
        return None


def policy_exists(policy_name):
    """Check if a policy exists with the given name and matches required tags."""
    return resource_exists(
        resource_name=policy_name,
        list_function=lambda: iam_client.get_paginator("list_policies"),
        name_key="PolicyName",
        tag_function=lambda arn: iam_client.list_policy_tags(PolicyArn=arn),
    )


def role_exists(role_name):
    """Check if a role exists with the given name and matches required tags."""
    return resource_exists(
        resource_name=role_name,
        list_function=lambda: iam_client.get_paginator("list_roles"),
        name_key="RoleName",
        tag_function=lambda arn: iam_client.list_role_tags(RoleName=role_name),
    )


def get_policies():
    """Retrieve all customer-managed policies from AWS."""
    try:
        paginator = iam_client.get_paginator("list_policies")
        policies = {}
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                policies[policy["PolicyName"]] = policy["Arn"]
        return policies
    except Exception as e:
        print(f"Error retrieving policies: {e}")
        return {}


def delete_policy(name, arn):
    try:
        iam_client.delete_policy(PolicyArn=arn)
        print(f"Policy {name} deleted successfully.")
    except Exception as e:
        print(f"Error deleting policy {name}: {e}")


def get_roles():
    """
    Retrieve all IAM roles, optionally filtering by a role path if specified in the environment variable.

    Returns:
        list: List of roles.
    """
    try:
        paginator = iam_client.get_paginator("list_roles")
        roles = []
        pagination_args = {}
        if role_path:
            pagination_args["PathPrefix"] = role_path
        for page in paginator.paginate(**pagination_args):
            roles.extend(page["Roles"])

        return roles
    except Exception as e:
        print(f"Error retrieving roles: {e}")
        return []


def detach_policies(role_name):
    """Detach all policies attached to a role."""
    try:
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"
        ]
        for policy in attached_policies:
            policy_arn = policy["PolicyArn"]
            try:
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                print(f"Detached policy {policy_arn} from role {role_name}.")
            except Exception as e:
                print(
                    f"Failed to detach policy {policy_arn} from role {role_name}: {e}"
                )
    except iam_client.exceptions.NoSuchEntityException:
        print(f"Role {role_name} does not exist.")
    except Exception as e:
        print(f"Failed to fetch attached policies for role {role_name}: {e}")


def delete_role(role_name):
    """
    Delete a role by name after detaching all attached policies.

    Args:
        role_name (str): The name of the role to delete.
    """
    if not role_exists(role_name):
        print(f"Role {role_name} does not exist or does not match required tags.")
        return

    detach_policies(role_name)
    try:
        iam_client.delete_role(RoleName=role_name)
        print(f"Role {role_name} deleted successfully.")
    except Exception as e:
        print(f"Error deleting role {role_name}: {e}")


def create_statements_action(role_type, args):
    output_dir = os.path.join(OUTPUT_DIR, role_type)
    if os.path.exists(output_dir):
        for filename in os.listdir(output_dir):
            file_path = os.path.join(output_dir, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f"Failed to delete {file_path}. Reason: {e}")
    process_pre_templates(role_type, args)
    templates = load_templates(role_type)
    processed_policies = process_templates(templates)
    for policy_name, policy_data in processed_policies.items():
        save_policy(role_type, policy_name, policy_data)


def delete_policies_action(role_type, args, preloaded_policies):
    """
    Delete policies for a given role type by reading processed policy files
    and checking if they already exist before creating them.
    """
    output_dir = os.path.join(OUTPUT_DIR, role_type)
    if not os.path.exists(output_dir):
        print(f"No policies found in output directory for {role_type}.")
        return

    for file_name in os.listdir(output_dir):
        if file_name.endswith(".json") and file_name != "trust_policy.json":
            file_path = os.path.join(output_dir, file_name)

            with open(file_path, "r", encoding="utf-8") as file:
                policy_data = json.load(file)

            policy_name = get_resource_name_from_filename(file_name)
            policy_arn = preloaded_policies.get(policy_name)
            if policy_arn:
                delete_policy(policy_name, policy_arn)
            else:
                print(
                    f"Policy {policy_name} does not exists in AWS (ARN: {policy_arn}). Skipping deletion."
                )


def create_policies_action(role_type, args, preloaded_policies):
    """
    Create policies for a given role type by reading processed policy files
    and checking if they already exist before creating them.
    """
    output_dir = os.path.join(OUTPUT_DIR, role_type)
    if not os.path.exists(output_dir):
        print(f"No policies found in output directory for {role_type}.")
        return

    for file_name in os.listdir(output_dir):
        if file_name.endswith(".json") and file_name != "trust_policy.json":
            file_path = os.path.join(output_dir, file_name)

            with open(file_path, "r", encoding="utf-8") as file:
                policy_data = json.load(file)

            policy_name = get_resource_name_from_filename(file_name)
            policy_arn = preloaded_policies.get(policy_name)
            if policy_arn:
                print(
                    f"Policy {policy_name} already exists in AWS (ARN: {policy_arn}). Skipping creation."
                )
            else:
                create_policy(policy_data, file_name)


def create_role_action(role_type, args, preloaded_roles):
    """
    Create a role for the given role type if it does not already exist.
    """
    role_name = get_role_name_by_access_type(role_type)
    existing_role = next(
        (role for role in preloaded_roles if role["RoleName"] == role_name), None
    )
    if existing_role:
        print(
            f"Role {role_name} already exists in AWS (ARN: {existing_role['Arn']}). Skipping creation."
        )
        return
    templates = load_templates(role_type)
    if "trust_policy.json" not in templates:
        print(f"Error: trust_policy.json is required for role creation in {role_type}.")
        return

    trust_policy = process_templates(
        {"trust_policy.json": templates["trust_policy.json"]}
    )["trust_policy.json"]
    create_role(role_type, trust_policy)
    attach_policies_action(role_type, args)


def get_resource_name_from_filename(file_name):
    base_name = os.path.splitext(file_name)[0]
    return "".join(
        word.title() for word in base_name.replace("_", " ").replace("-", " ").split()
    )


def attach_policies_action(role_type, args):
    """Attach all defined policies in the role-type folder to the role if they exist in AWS."""
    role_name = role_names[role_type]

    try:
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"
        ]
        attached_policy_arns = {policy["PolicyArn"] for policy in attached_policies}
    except iam_client.exceptions.NoSuchEntityException:
        print(f"Error: Role {role_name} does not exist.")
        return
    except Exception as e:
        print(f"Failed to fetch attached policies for role {role_name}: {e}")
        return

    role_template_dir = os.path.join(TEMPLATE_DIR, "post", role_type)
    if not os.path.exists(role_template_dir):
        print(f"No policy templates found for role type {role_type}.")
        return

    for file_name in os.listdir(role_template_dir):
        if file_name.endswith(".json") and file_name != "trust_policy.json":
            file_path = os.path.join(role_template_dir, file_name)

            with open(file_path, "r", encoding="utf-8") as file:
                policy_data = json.load(file)

            policy_name = get_resource_name_from_filename(file_name)
            policy_arn = policy_exists(policy_name)

            if policy_arn:
                if policy_arn not in attached_policy_arns:
                    try:
                        iam_client.attach_role_policy(
                            RoleName=role_name, PolicyArn=policy_arn
                        )
                        print(f"Policy {policy_name} attached to role {role_name}.")
                    except Exception as e:
                        print(
                            f"Failed to attach policy {policy_name} to role {role_name}: {e}"
                        )
                else:
                    print(
                        f"Policy {policy_name} is already attached to role {role_name}."
                    )
            else:
                print(
                    f"Policy {policy_name} does not exist in AWS. Please create it before attaching."
                )


def create_all(role_type, args):
    create_statements_action(role_type, args)
    preloaded_policies = get_policies()
    create_policies_action(role_type, args, preloaded_policies)
    preloaded_roles = get_roles()
    create_role_action(role_type, args, preloaded_roles)


def delete_all(role_type, args):
    role_name = get_role_name_by_access_type(role_type)
    detach_policies(role_name)
    delete_role(role_name)
    preloaded_policies = get_policies()
    delete_policies_action(role_type, args, preloaded_policies)


def main():
    role_types = role_names.keys()
    parser = argparse.ArgumentParser(
        description="Manage IAM roles and policies for Cross Account Roles."
    )
    parser.add_argument(
        "--role-type",
        required=False,
        help="Role type for policies and role. If undefined, CLI runs all",
    )
    parser.add_argument(
        "--action",
        choices=[
            "create",
            "copy-example",
            "setup-defaults",
            "create-pre-template",
            "process-pre-template",
            "create-statements",
            "create-policies",
            "create-role",
            "init-role",
            "attach-policies",
            "get-policies",
            "delete-policies",
            "get-roles",
            "delete-role",
            "delete",
        ],
        required=True,
        help="Action to perform.",
    )
    parser.add_argument(
        "--template-name",
        required=False,
        help="Name of template to create or to copy from examples/templates",
    )
    parser.add_argument(
        "--role-name",
        required=False,
        help="Name of role to create. Used in init-role",
    )

    args = parser.parse_args()
    setup_actions = ["init-role", "copy_example"]
    if (
        args.action != setup_actions
        and args.role_type
        and args.role_type not in role_types
    ):
        parser.error(
            f"Invalid role type '{args.role_type}'. Expected one of {list(role_types)}"
        )
    current_role_types = [args.role_type] if args.role_type else role_types
    preloaded_roles = get_roles() if args.action == "create-role" else None
    preloaded_policies = (
        get_policies()
        if args.action == "create-policies" or args.action == "delete-policies"
        else None
    )
    role_type_actions = {
        "copy-example": copy_example,
        "create-pre-template": create_policy_sentry_template,
        "process-pre-template": process_pre_templates,
        "init-role": initialize_role,
        "create-statements": create_statements_action,
        "create-policies": lambda role_type, args: create_policies_action(
            role_type, args, preloaded_policies
        ),
        "delete-policies": lambda role_type, args: delete_policies_action(
            role_type, args, preloaded_policies
        ),
        "create-role": lambda role_type, args: create_role_action(
            role_type, args, preloaded_roles
        ),
        "attach-policies": attach_policies_action,
        "create": create_all,
        "delete": delete_all,
    }
    if args.action in role_type_actions:
        for role_type in current_role_types:
            role_type_actions[args.action](role_type, args)

    elif args.action == "get-policies":
        policies = get_policies()
        for policy in policies:
            print(f"Policy Name: {policy}")

    elif args.action == "get-roles":
        roles = get_roles()
        for role in roles:
            print(f"Role: {role['RoleName']} (ARN: {role['Arn']})")

    elif args.action == "delete-role":
        for access_type in current_role_types:
            delete_role(get_role_name_by_access_type(access_type))
    elif args.action == "setup-defaults":
        setup_defaults()


check_roles_file()
if __name__ == "__main__":
    main()
