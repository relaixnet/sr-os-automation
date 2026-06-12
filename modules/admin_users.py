import random
import string

from pysros.management import Connection

from lib.validation import safe_get
from ._base_module import BaseModule


def key_to_key_dict(key: str) -> dict:
    key_data = {}
    key_split = key.split(" ")
    if len(key_split) >= 2:
        key_data["key-value"] = key_split[1]  # drop "ecdsa-sha2-nistp256" or "ssh-rsa"
        if len(key_split) >= 3:
            # extract comment
            key_split.pop(0)  # drop rest of split
            key_split.pop(0)  # drop rest of split
            key_data["description"] = " ".join(key_split)
    else:
        key_data["key-value"] = key_split[0]
    return key_data


class AdminUsersModule(BaseModule):
    def validate_config(self) -> None:
        # validate config
        for user, user_config in self.config.items():
            if safe_get(user_config, "reset_password"):
                if type(safe_get(user_config, "reset_password")) != bool:
                    self.raise_exception(f"User {user}: The setting 'reset_password' has to be of type boolean!")
            if not safe_get(user_config, "ssh_keys"):
                continue
            if safe_get(user_config, "ssh_keys", "rsa"):
                if type(safe_get(user_config, "ssh_keys", "rsa")) != list:
                    self.raise_exception(f"RSA keys for user {user} are not given as list!")
            if safe_get(user_config, "ssh_keys", "ecdsa"):
                if type(safe_get(user_config, "ssh_keys", "ecdsa")) != list:
                    self.raise_exception(f"ECDSA keys for user {user} are not given as list!")

    def run(self, connection: Connection) -> None:
        config_group = "auto_admin_users"
        # try reading running config for passwords
        try:
            current_content = connection.running.get(f'/configure/groups/group[name="{config_group}"]')
        except LookupError:
            current_content = {}

        passwords = {}

        if current_content:
            current_users = safe_get(current_content, "system", "security", "user-params", "local-user", "user")
            if current_users:
                for user, user_settings in current_users.items():
                    if "password" in user_settings:
                        passwords[user] = str(user_settings["password"])

        users = {}

        for user, user_settings in self.config.items():
            reset_password = safe_get(user_settings, "reset_password")

            if user in passwords and not reset_password:
                password = passwords[user]
            else:
                password = ''.join(
                    random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(20))

            rsa_keys = {}
            ecdsa_keys = {}

            if safe_get(user_settings, "ssh_keys", "rsa"):
                counter = 1
                for key in safe_get(user_settings, "ssh_keys", "rsa"):
                    key_data = key_to_key_dict(key)
                    rsa_keys[counter] = key_data
                    counter += 1

            if safe_get(user_settings, "ssh_keys", "ecdsa"):
                counter = 1
                for key in safe_get(user_settings, "ssh_keys", "ecdsa"):
                    key_data = key_to_key_dict(key)
                    ecdsa_keys[counter] = key_data
                    counter += 1

            users[user] = {
                'password': password,
                # default settings
                'console': {
                    'member': ['administrative'],
                },
                'restricted-to-home': False,
                'save-when-restricted': False,
                'access': {
                    'console': True,
                    'netconf': True,
                },
            }

            if rsa_keys or ecdsa_keys:
                users[user]['public-keys'] = {}
                if rsa_keys:
                    users[user]['public-keys']['rsa'] = {
                        'rsa-key': rsa_keys,
                    }
                if ecdsa_keys:
                    users[user]['public-keys']['ecdsa'] = {
                        'ecdsa-key': ecdsa_keys,
                    }

        group = {
            'system': {
                'security': {
                    'user-params': {
                        'local-user': {
                            'user': users
                        }
                    }
                }
            }
        }

        connection.candidate.set(f'/configure/groups/group[name="{config_group}"]', group, method="replace",
                                 commit=False)
