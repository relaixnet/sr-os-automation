#!/usr/bin/env python3

import argparse
import os
import re
import subprocess
import sys
from getpass import getpass

import yaml
from rich import print

from lib.pysros import connect
from modules import *

script_location = os.path.dirname(os.path.realpath(__file__))
config_location = f"{script_location}/config.yaml"
secrets_config_location = f"{script_location}/secrets.yaml"

module_map = {
    "admin_users": AdminUsersModule,
    "base_config": BaseConfigModule,
    "block_lists": BlockListsModule,
    "emergency_admin": EmergencyAdminModule,
    "peerings": PeeringsModule,
    "policies": PoliciesModule,
}


def main() -> int:
    parser = argparse.ArgumentParser(
        prog='apply.py',
        description='SR OS NETCONF automation'
    )

    parser.add_argument("-c", "--config", help="Path to the Config-File")
    parser.add_argument("-s", "--secretsconfig", help="Path to the secrets Config-File")
    parser.add_argument("-m", "--modules", help="Comma separated list of modules to run")
    parser.add_argument("-t", "--timeout", help="NETCONF timeout in seconds (default 300)", default=300, type=int)
    parser.add_argument("-u", "--user", help="Username to use (default 'admin')", default="admin", type=str)
    parser.add_argument("-p", "--password", help="Password for the user (default 'admin')", default="admin", type=str)
    parser.add_argument("--askpass", action="store_true", help="Ask for password (overrides the --password flag)")
    parser.add_argument("--commit", action="store_true", help="Commit changes")
    parser.add_argument("--commit_yes", action="store_true", help="Commit changes without asking")
    parser.add_argument("--diff", action="store_true", help="Print diff")
    parser.add_argument("target", help="Deployment target host")

    args = parser.parse_args()

    if not args.modules:
        print("No modules given, exiting.")
        return 1

    if args.timeout < 1:
        print(f"Invalid timeout value {args.timeout}, exiting.")
        return 1

    final_config_location = args.config if args.config else config_location
    final_secrets_config_location = args.secretsconfig if args.secretsconfig else secrets_config_location

    if not os.path.exists(final_config_location):
        print("No configuration file found!")
        return 1

    with open(final_config_location, 'r') as f:
        config_text = f.read()

    config = yaml.safe_load(config_text)
    # Validate Top-Level configuration keys
    required_config_keys = [
        "repo",
        "verify_hostkey",
        "module_config",
    ]
    for key in required_config_keys:
        if key not in config:
            print(f"Setting '{key}' is not defined in configuration file!")
            return 1

    # Validate local git repo constraints
    required_repo_config_keys = [
        "force_up_to_date",
        "force_clean_worktree",
        "force_main_branch",
    ]
    for key in required_repo_config_keys:
        if key not in config["repo"]:
            print(f"Setting 'repo[\"{key}\"]' is not defined in configuration file!")
            return 1

    repo_force_up_to_date = config["repo"]["force_up_to_date"]
    repo_force_clean_worktree = config["repo"]["force_clean_worktree"]
    repo_force_main_branch = config["repo"]["force_main_branch"]

    any_repo_constraint = repo_force_up_to_date or repo_force_clean_worktree or repo_force_main_branch

    if any_repo_constraint:
        # backup old working directory
        working_directory = os.getcwd()

        # cd to script location
        os.chdir(script_location)

        if not os.path.exists("./.git"):
            print("Could not find local git repository, exiting!")
            return 1

        git_status = subprocess.run(["git", "status"], capture_output=True, text=True)
        matches = re.search(r"On branch (\S+)", git_status.stdout)
        if not matches:
            print("Failed to parse git output, refusing to run!")
            return 1

        branch = matches.group(1)

        if repo_force_main_branch:
            if branch != "main":
                print("Not on main branch in git repository, refusing to run!")
                return 1

        if repo_force_clean_worktree:
            if not "nothing to commit, working tree clean" in git_status.stdout:
                print("Local changes detected in git repository, refusing to run!")
                return 1

        if repo_force_up_to_date:
            git_pull_dry = subprocess.run(["git", "pull", "--dry-run", "-v"], capture_output=True, text=True)
            matches = re.search(r"\[up to date] +" + branch, git_pull_dry.stderr)

            with open(f"./.git/refs/remotes/origin/{branch}", "r") as f:
                remote_head = f.read().strip()

            with open(f"./.git/refs/heads/{branch}") as f:
                current_head = f.read().strip()

            if not matches or remote_head != current_head:
                print("Current git branch is not up to date, refusing to run!")
                return 1

        # cd back to old working directory
        os.chdir(working_directory)

    if os.path.exists(final_secrets_config_location):
        with open(final_secrets_config_location, 'r') as f:
            secrets_config_text = f.read()

        secrets_config = yaml.safe_load(secrets_config_text)
    else:
        if args.secretsconfig:
            # only complain and abort if secrets config is explicitly given
            print("Could not find given secrets configuration file!")
            return 1
        secrets_config = {}

    loaded_modules = []

    requested_modules = args.modules.split(",")

    # Get enabled modules and parse module configs
    for config_module in requested_modules:
        if config_module not in module_map:
            print(f"Module '{config_module}' is not defined, exiting!")
            return 1

        module = module_map[config_module]()  # instanciate module

        # Set and validate module config
        module.config = config["module_config"][config_module]
        module.secrets_config = secrets_config

        try:
            module.validate_config()
        except ModuleException as e:
            print("Module config validation aborted with exception:")
            print(str(e))
            print()
            print("Aborting.")
            return 1

        loaded_modules.append(module)

    if not loaded_modules:
        print("No modules loaded, exiting.")
        return 1

    user = args.user
    password = args.password
    if args.askpass:
        password = getpass("Password: ")

    connection = connect(args.target, user, password, port=830,
                         timeout=args.timeout, hostkey_verify=config["verify_hostkey"])

    for module in loaded_modules:
        try:
            module.run(connection)
        except ModuleException as e:
            connection.candidate.discard()
            connection.disconnect()
            print("Module run aborted with exception:")
            print(str(e))
            print()
            print("All changes are discarded, aborting.")
            return 1

    if args.diff:
        print(connection.candidate.compare(output_format="md-cli"))

    if args.commit:
        if args.commit_yes:
            connection.candidate.commit()
        else:
            confirmation = input("Commit these changes? [y/N] ").lower()
            if confirmation == "y":
                connection.candidate.commit()
                print("Committed changes.")
            else:
                connection.candidate.discard()
                print("Commit not confirmed, discarding changes.")

    for module in loaded_modules:
        module.post_run()

    connection.disconnect()
    return 0


if __name__ == '__main__':
    sys.exit(main())
