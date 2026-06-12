from typing import Any

from pysros.management import Connection

from lib.pysros import get_version
from ._base_module import BaseModule


class BaseConfigModule(BaseModule):
    def run(self, connection: Connection) -> None:
        config_group = "auto_base_config"

        # randomly generated example SSH key
        oxidized_ssh_key = "AAAAB3NzaC1yc2EAAAADAQABAAABAQCggSs5GxzHwAUeALTYTshDUps9F2JurB1JI2njAmeHPRBsjVK9z6M6qWvggJ235WzlMHfaFD8ifsnxAdoNzPoRZaBxnCOxR0KmzUA2T3Izcgl3HzL6Pj3shJpI4JZOhKTO+KON1kcyHh5W+fmR+FS+Nmr6O9Nz12jGeeR/kE4hWegIPZyWxxmo1eXXv8+hD7XODH4rEylnfplY+Vm2BE4csXjS1qmiE4z0ySD7wongji1u+/NAVWNDfzAAiI+9W2/0BKw81ecpBQUle8R8Qoxe6spSzI5gP5bKcIafWbm71dZfohqm+1KpisF14SzDkpjP61Z0SB9czbznVF6Fb6kB"

        group: dict[str, Any] = {
            "log": {
                "syslog": {
                    "1": {
                        "address": "10.0.0.1",
                    }
                },
                "log-id": {
                    "10": {
                        "source": {
                            "main": True
                        },
                        "destination": {
                            "syslog": "1",
                        },
                    },
                }
            },
            "system": {
                "time": {
                    "zone": {
                        "standard": {
                            "name": "cet"
                        }
                    },
                    "ntp": {
                        "admin-state": "enable",
                        "server": {
                            ("10.0.0.2", "Base"): {},
                        }
                    }
                },
                "security": {
                    "source-address": {
                        "ipv4": {
                            "syslog": {
                                "interface-name": "system",
                            },
                            "ntp": {
                                "interface-name": "system",
                            }
                        }
                    },
                    "snmp": {
                        "community": {
                            "secretsnmpcommunity": {
                                "access-permissions": "r",
                            }
                        }
                    },
                    "ssh": {
                        "preserve-key": True,
                    },
                    "aaa": {
                        "local-profiles": {
                            "profile": {
                                "oxidized": {
                                    "entry": {
                                        1: {
                                            "match": "logout",
                                            "action": "permit",
                                        },
                                        2: {
                                            "match": "environment",
                                            "action": "permit",
                                        },
                                        10: {
                                            "match": "admin show configuration",
                                            "action": "permit",
                                        },
                                        20: {
                                            "match": "show chassis",
                                            "action": "permit",
                                        },
                                        30: {
                                            "match": "show system information",
                                            "action": "permit",
                                        },
                                        40: {
                                            "match": "show card state",
                                            "action": "permit",
                                        },
                                        100: {
                                            "action": "deny",
                                        },
                                    }
                                }
                            }
                        }
                    },
                    "user-params": {
                        "local-user": {
                            "user": {
                                "oxidized": {
                                    "password": "secretoxidizedpassword",
                                    "access": {
                                        "console": True,
                                    },
                                    "console": {
                                        "member": ["oxidized"],
                                    },
                                    'restricted-to-home': False,
                                    'save-when-restricted': False,
                                    "public-keys": {
                                        "rsa": {
                                            "rsa-key": {
                                                1: {
                                                    "description": "oxidized",
                                                    "key-value": oxidized_ssh_key,
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        version = get_version(connection)

        if version.major > 23:
            group["system"]["time"]["daylight-saving-time-zone"] = {
                "standard": {
                    "name": "cest",
                }
            }
        else:
            group["system"]["time"]["dst-zone"] = {
                "CEST": {
                    "start": {
                        "week": "last",
                        "month": "march",
                        "hours-minutes": "02:00",
                    },
                    "end": {
                        "week": "last",
                        "month": "october",
                        "hours-minutes": "03:00",
                    }
                }
            }

        connection.candidate.set(f'/configure/groups/group[name="{config_group}"]', group, method="replace",
                                 commit=False)
