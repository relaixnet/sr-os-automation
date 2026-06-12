from pysros.management import Connection
from pysros.singleton import Empty

from lib.validation import safe_get
from ._base_module import BaseModule


class BlockListsModule(BaseModule):
    def validate_config(self) -> None:
        ipv4 = safe_get(self.config, "ipv4")
        ipv6 = safe_get(self.config, "ipv6")

        if not ipv4:
            self.raise_exception("The IPv4 block list must not be empty! (Would block all traffic otherwise)")

        if not ipv6:
            self.raise_exception("The IPv6 block list must not be empty! (Would block all traffic otherwise)")

    def run(self, connection: Connection) -> None:
        config_group = "auto_block_lists"

        ipv4_dict = {prefix: {} for prefix in self.config["ipv4"]}
        ipv6_dict = {prefix: {} for prefix in self.config["ipv6"]}

        group = {
            "filter": {
                "match-list": {
                    "ip-prefix-list": {
                        "BLOCK-INCOMING": {
                            "prefix": ipv4_dict
                        }
                    },
                    "ipv6-prefix-list": {
                        "BLOCK-INCOMING": {
                            "prefix": ipv6_dict
                        }
                    },
                },
                "ip-filter": {
                    "INBOUND-CONTROL": {
                        "default-action": "accept",
                        "filter-id": 2000,
                        "entry": {
                            10: {
                                "match": {
                                    "src-ip": {
                                        "ip-prefix-list": "BLOCK-INCOMING"
                                    }
                                },
                                "action": {
                                    "drop": Empty
                                }
                            }
                        }
                    }
                },
                "ipv6-filter": {
                    "INBOUND-CONTROL": {
                        "default-action": "accept",
                        "filter-id": 2000,
                        "entry": {
                            10: {
                                "match": {
                                    "src-ip": {
                                        "ipv6-prefix-list": "BLOCK-INCOMING"
                                    }
                                },
                                "action": {
                                    "drop": Empty
                                }
                            }
                        }
                    }
                }
            }
        }

        connection.candidate.set(f'/configure/groups/group[name="{config_group}"]', group, method="replace",
                                 commit=False)
