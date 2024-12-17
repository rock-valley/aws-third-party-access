import json
import yaml
from policy_sentry.command.write_policy import write_policy_with_template
from policy_sentry.querying.arns import get_raw_arns_for_service
from policy_sentry.writing.template import create_crud_template
from policy_sentry.util.file import read_yaml_file
from policy_sentry.writing.template import get_crud_template_dict

from itertools import chain
import os


def create_ps_template(directory, name, **kwargs):
    file_path = f"{directory}/{name}.yaml"
    if kwargs["services"] is not None:
        services = [i.strip() for i in kwargs.get("services", "").split(",")]
        if len(services) > 0:
            crud_template = get_crud_template_dict()
            arns = list(
                chain.from_iterable(list(map(get_raw_arns_for_service, services)))
            )
            crud_template["read"] = arns
            with open(file_path, "w") as yaml_file:
                yaml.dump(crud_template, yaml_file, default_flow_style=False)
    else:
        crud_template = create_crud_template()
        save_yaml_template(file_path, crud_template)


def save_yaml_template(file_path, template):
    with open(file_path, "w", encoding="utf-8") as file:
        for line in template:
            file.write(line)


def create_policy_from_ps_template(pre_dir, post_dir, name):
    yaml_file_path = os.path.join(pre_dir, name)
    cfg = read_yaml_file(yaml_file_path)
    policy = write_policy_with_template(cfg)
    base_name, _ = os.path.splitext(name)
    data = json.dumps(policy, indent=4)
    with open(f"{post_dir}/{base_name}.json", "w", encoding="utf-8") as file:
        file.write(data)
