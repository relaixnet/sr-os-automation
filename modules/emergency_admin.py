import random
import string

from pysros.management import Connection

from lib.validation import safe_get
from ._base_module import BaseModule


class EmergencyAdminModule(BaseModule):
    def __init__(self) -> None:
        super().__init__()
        self.password = ""

    def validate_config(self) -> None:
        if not safe_get(self.config, "enabled"):
            self.raise_exception(
                "The EmergencyAdmin Module needs to be explicitly enabled in the configuration, aborting!"
            )

    def run(self, connection: Connection) -> None:
        config_group = "auto_emergency_admin"

        self.password = ''.join(
            random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(20))

        group = {
            "system": {
                "security": {
                    "system-passwords": {
                        "admin-password": self.password,
                    },
                    "user-params": {
                        "local-user": {
                            "user": {
                                "admin": {
                                    "password": self.password,
                                    "restricted-to-home": False,
                                    'save-when-restricted': False,
                                    "console": {
                                        "member": ["administrative"]
                                    },
                                    "access": {
                                        "console": True,
                                        "netconf": True,
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        connection.candidate.set(f'/configure/groups/group[name="{config_group}"]', group, method="replace",
                                 commit=False)

    def post_run(self) -> None:
        print()
        print(f"New admin password: {self.password}")
