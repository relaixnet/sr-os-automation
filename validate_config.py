#!/usr/bin/env python3

import os
import sys

import yaml

script_location = os.path.dirname(os.path.realpath(__file__))
config_location = f"{script_location}/config.yaml"


def validate_config(
        actual_config: dict,
        expected_config: dict,
        recursion_stack: str = "",
        recursion_result: bool = True,
) -> bool:
    result = recursion_result
    for key, value in expected_config.items():
        if key not in actual_config:
            print(f"Expected key '{key}' not found in 'config{recursion_stack}'!")
            result = False
            continue

        if type(value) == dict:
            new_recursion_stack = recursion_stack + f'["{key}"]'
            result = validate_config(actual_config[key], value, new_recursion_stack, result)
        else:
            actual_value = actual_config[key]
            if actual_value != value:
                print(
                    f"Value of key '{key}' in 'config{recursion_stack}' is '{actual_value}' instead of expected '{value}'!"
                )
                result = False
    return result


def main() -> int:
    with open(config_location, "r") as f:
        config_text = f.read()

    config = yaml.safe_load(config_text)

    expected_config = {
        "verify_hostkey": True,
        "repo": {
            "force_up_to_date": True,
            "force_clean_worktree": True,
            "force_main_branch": True,
        },
        "module_config": {
            "emergency_admin": {
                "enabled": False,
            },
            "peerings": {
                "deploy_irr_filters": False,
            }
        }
    }

    result = validate_config(config, expected_config)

    if not result:
        return 1

    print("All expected configuration keys have their expected values :)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
