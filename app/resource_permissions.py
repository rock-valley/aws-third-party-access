import json
import yaml
from policy_sentry.command.write_policy import write_policy_with_template
from policy_sentry.writing.template import create_crud_template
from policy_sentry.util.file import read_yaml_file
import os


def create_ps_template(directory, name):
    crud_template = create_crud_template()
    file_path = f"{directory}/{name}.yaml"
    with open(file_path, "w", encoding="utf-8") as file:
        for line in crud_template:
            file.write(line)


def create_policy_from_ps_template(pre_dir, post_dir, name):
    yaml_file_path = os.path.join(pre_dir, name)
    cfg = read_yaml_file(yaml_file_path)
    policy = write_policy_with_template(cfg)
    base_name, _ = os.path.splitext(name)
    data = json.dumps(policy, indent=4)
    with open(f"{post_dir}/{base_name}.json", "w", encoding="utf-8") as file:
        file.write(data)
