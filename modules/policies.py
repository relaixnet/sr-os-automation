import copy
import typing

from pysros.management import Connection

from ._base_module import BaseModule


def generate_policy_for_template(template_policy_name: str, description: str, variables: dict) -> dict:
    formatted_vars = dict()

    for key, value in variables.items():
        formatted_vars[f"@{key}@"] = {
            "value": value
        }

    return {
        "description": description,
        "entry": {
            10: {
                "from": {
                    "policy": template_policy_name,
                    "policy-variables": {
                        "name": formatted_vars
                    }
                },
                "action": {
                    "action-type": "accept"
                }
            }
        },
        "default-action": {
            "action-type": "reject"
        }
    }


def generate_bgp_import_peer_policy(prefix_list_name: str, asn: int) -> dict:
    return generate_policy_for_template(
        template_policy_name="bgp-import-peer-template",
        description=f"import policy for peer AS{asn} with IRR filters",
        variables={"prefix-list": prefix_list_name}
    )


def generate_bgp_import_private_peer_policy(prefix_list_name: str, asn: int) -> dict:
    return generate_policy_for_template(
        template_policy_name="bgp-import-private-peer-template",
        description=f"import policy for private peer AS{asn} with IRR filters",
        variables={"prefix-list": prefix_list_name}
    )


def generate_bgp_export_peer_steering_communities_policy(steering_community_name: str, asn: int) -> dict:
    return generate_policy_for_template(
        template_policy_name="bgp-export-peer-steering-communities-template",
        description=f"export policy with steering communities for peer AS{asn}",
        variables={"steering-community": steering_community_name}
    )


def generate_bgp_import_transit_policy(prefix_list_name: str, asn: int) -> dict:
    return generate_policy_for_template(
        template_policy_name="bgp-import-transit-template",
        description=f"import policy for transit AS{asn}",
        variables={"prefix-list": prefix_list_name}
    )


def generate_bgp_import_customer_policy(prefix_list_name: str, as_path_group_name: str, asn: int) -> dict:
    return generate_policy_for_template(
        template_policy_name="bgp-import-customer-template",
        description=f"import policy for customer peer AS{asn}",
        variables={
            "prefix-list": prefix_list_name,
            "aspath-group": as_path_group_name,
            "stripped-community": "rx-all-own-communities"
        }
    )


def generate_bgp_import_customer_policy_soft_community_restrictions(
        prefix_list_name: str, as_path_group_name: str, asn: int
) -> dict:
    return generate_policy_for_template(
        template_policy_name="bgp-import-customer-template",
        description=f"import policy for customer peer AS{asn}",
        variables={
            "prefix-list": prefix_list_name,
            "aspath-group": as_path_group_name,
            # strip only internal communities and allow rest like DDoS-Steering-Communities
            "stripped-community": "rx-internal-communities"
        }
    )


class PoliciesModule(BaseModule):
    def run(self, connection: Connection) -> None:
        config_group = "auto_policies"

        # Policy-Generation
        ## Static prefix lists

        prefix_lists = {
            "bogons": {
                "prefix": {
                    ("0.0.0.0/0", "exact"): {},
                    ("0.0.0.0/8", "longer"): {},
                    ("10.0.0.0/8", "longer"): {},
                    ("100.64.0.0/10", "longer"): {},
                    ("127.0.0.0/8", "longer"): {},
                    ("169.254.0.0/16", "longer"): {},
                    ("172.16.0.0/12", "longer"): {},
                    ("192.0.0.0/24", "longer"): {},
                    ("192.0.2.0/24", "longer"): {},
                    ("192.168.0.0/16", "longer"): {},
                    ("198.18.0.0/15", "longer"): {},
                    ("198.51.100.0/24", "longer"): {},
                    ("203.0.113.0/24", "longer"): {},
                    ("224.0.0.0/4", "longer"): {},
                    ("240.0.0.0/4", "longer"): {},
                    ("255.255.255.255/32", "exact"): {},
                    ("::/0", "exact"): {},
                    ("::/128", "exact"): {},
                    ("::1/128", "exact"): {},
                    ("::ffff:0.0.0.0/96", "longer"): {},
                    ("100::/64", "longer"): {},
                    ("2001::/23", "longer"): {},
                    ("2001:db8::/32", "longer"): {},
                    ("2002::/16", "range"): {
                        "start-length": 17,
                        "end-length": 128,
                    },
                    ("3ffe::/16", "longer"): {},
                    ("5f00::/8", "longer"): {},
                    ("fc00::/7", "longer"): {},
                    ("fe80::/10", "longer"): {},
                    ("ff00::/8", "longer"): {},
                }
            },
            "default-route": {
                "prefix": {
                    ("0.0.0.0/0", "exact"): {},
                    ("::/0", "exact"): {},
                }
            },
            "ixp-peering-lans": {
                "prefix": {
                    # Imagine-IX 1
                    ("10.0.1.0/24", "longer"): {},
                    ("fd1a:8f9a:b18e::/64", "longer"): {},
                    # Imagine-IX 2
                    ("10.0.2.0/24", "longer"): {},
                    ("fd77:b672:8380::/48", "longer"): {},
                }
            },
            "rx-bgp-announce": {
                # we just ensure the existence of this prefix list,
                # the list will still be populated manually on the router
            },
            "too-small-prefixes": {
                "prefix": {
                    ("0.0.0.0/0", "range"): {
                        "start-length": 25,
                        "end-length": 32,
                    },
                    ("::/0", "range"): {
                        "start-length": 49,
                        "end-length": 128,
                    }
                }
            },
        }

        ## Static communities

        communities = {
            "gshut": {
                "member": {
                    "65535:0": {}
                }
            },
            "no-export": {
                "member": {
                    "no-export": {}
                }
            },
            # example route target for our internet VRF
            "rt-64600-54321": {
                "member": {
                    "target:64600:54321": {}
                }
            },
            # example route target for default routes from our internet VRF
            "rt-64600-54322": {
                "member": {
                    "target:64600:54322": {}
                }
            },
            "rx-action-antiddos": {
                "expression": {
                    "expr": "64600:12345 OR 64600:12346" # example communities
                },
            },
            "rx-all-own-communities": {
                # all of our own communities, stripped on most imports
                # possible exceptions like DDoS customers are restricted to
                # rx-internal-communities (see below)
                "member": {
                    "^64600$:(.*)": {}, # regex for all example communities above
                    "^34953$:(.*)": {},
                    "target:^64600$&(.*)": {}, # regex for all example route-targets above
                }
            },
            "rx-internal-communities": {
                # internal communities, stripped in any case on import
                "member": {
                    "^34953$:^1[0-9][0-9][0-9][0-9]$": {},
                    "target:^64600$&(.*)": {}, # regex for all example route-targets above
                }
            },
            "rx-steering-communities-and-route-targets": {
                # steering communities and route targets, stripped in any case on export
                "member": {
                    "^64600$:^1234[5-6]$": {}, # regex for the example ddos communitiy above
                    "target:^64600$&(.*)": {},
                }
            },
            "rx-origin-local": {
                "member": {
                    "34953:10000": {}
                }
            },
            "rx-origin-customers": {
                "member": {
                    "34953:10001": {}
                }
            },
            "rx-origin-privatepeers": {
                "member": {
                    "34953:10002": {}
                }
            },
            "rx-origin-peers": {
                "member": {
                    "34953:10003": {}
                }
            },
            "rx-origin-transit": {
                "member": {
                    "34953:10004": {}
                }
            },
        }

        ## Static policies
        policy_accept_all: dict[str, typing.Any] = {
            "default-action": {
                "action-type": "accept"
            }
        }

        policy_drop_all: dict[str, typing.Any] = {
            "default-action": {
                "action-type": "reject"
            }
        }

        entry_reject_too_small = {
            "description": "reject too small prefixes",
            "from": {
                "prefix-list": ["too-small-prefixes"]
            },
            "action": {
                "action-type": "reject"
            }
        }

        entry_reject_bogons = {
            "description": "reject bogons",
            "from": {
                "prefix-list": ["bogons"]
            },
            "action": {
                "action-type": "reject"
            }
        }

        entry_reject_peering_lans = {
            "description": "reject IXP peering LANs",
            "from": {
                "prefix-list": ["ixp-peering-lans"]
            },
            "action": {
                "action-type": "reject"
            }
        }

        entry_reject_ddos_routes = {
            "description": "reject DDoS protected routes",
            "from": {
                "community": {
                    "name": "rx-action-antiddos"
                }
            },
            "action": {
                "action-type": "reject"
            }
        }

        entry_permit_route_injection = {
            "description": "permit route-injection",
            "from": {
                "prefix-list": ["rx-bgp-announce"],
                "protocol": {
                    "name": ["static"]
                }
            },
            "action": {
                "action-type": "accept",
                "origin": "igp",
                "community": {
                    "add": ["rx-origin-local"],
                    "remove": ["rx-steering-communities-and-route-targets"],
                }
            }
        }

        entry_permit_local_routes = {
            "description": "permit local routes",
            "from": {
                "community": {
                    "name": "rx-origin-local"
                }
            },
            "action": {
                "action-type": "accept",
                "community": {
                    "remove": ["rx-steering-communities-and-route-targets"],
                }
            }
        }

        entry_permit_customer_routes = {
            "description": "permit customer routes",
            "from": {
                "community": {
                    "name": "rx-origin-customers"
                }
            },
            "action": {
                "action-type": "accept",
                "community": {
                    "remove": ["rx-steering-communities-and-route-targets"],
                }
            }
        }

        policy_bgp_export_peer: dict[str, typing.Any] = {
            "description": "simple default export policy for peerings",
            "entry": {
                10: entry_reject_too_small,
                20: entry_reject_bogons,
                30: entry_reject_peering_lans,
                40: entry_reject_ddos_routes,
                50: entry_permit_route_injection,
                60: entry_permit_local_routes,
                70: entry_permit_customer_routes,
            },
            "default-action": {
                "action-type": "reject"
            }
        }

        policy_bgp_export_peer_path_prepend: dict[str, typing.Any] = copy.deepcopy(policy_bgp_export_peer)
        policy_bgp_export_peer_path_prepend["description"] = \
            "simple default export policy for peerings with 5 path prepends"
        policy_bgp_export_peer_path_prepend["entry"][50]["action"]["as-path-prepend"] = {
            "as-path": 34953,
            "repeat": 5,
        }
        policy_bgp_export_peer_path_prepend["entry"][60]["action"]["as-path-prepend"] = {
            "as-path": 34953,
            "repeat": 5,
        }
        policy_bgp_export_peer_path_prepend["entry"][70]["action"]["as-path-prepend"] = {
            "as-path": 34953,
            "repeat": 5,
        }

        policy_bgp_import_peer: dict[str, typing.Any] = {
            "description": "simple default import policy for peerings",
            "entry": {
                10: entry_reject_too_small,
                20: entry_reject_bogons,
                30: entry_reject_peering_lans,
                40: {
                    "from": {
                        "community": {
                            "name": "gshut"
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "local-preference": 0,
                        "community": {
                            "add": ["rx-origin-peers"],
                            "remove": ["rx-all-own-communities"],
                        }
                    }
                },
                50: {
                    "from": {
                        "community": {
                            "name": "no-export"
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "local-preference": 90,
                        "community": {
                            "add": ["rx-origin-peers"],
                            "remove": ["rx-all-own-communities"],
                        }
                    }
                },
            },
            "default-action": {
                "action-type": "accept",
                "community": {
                    "add": ["rx-origin-peers"],
                    "remove": ["rx-all-own-communities"],
                }
            }
        }

        policy_bgp_import_private_peer: dict[str, typing.Any] = copy.deepcopy(policy_bgp_import_peer)
        policy_bgp_import_private_peer["description"] = "simple default import policy for private peerings"
        policy_bgp_import_private_peer["entry"][40]["action"]["community"] = {
            "add": ["rx-origin-privatepeers"],
            "remove": ["rx-all-own-communities"],
        }
        policy_bgp_import_private_peer["entry"][50]["action"]["community"] = {
            "add": ["rx-origin-privatepeers"],
            "remove": ["rx-all-own-communities"],
        }
        policy_bgp_import_private_peer["default-action"]["community"] = {
            "add": ["rx-origin-privatepeers"],
            "remove": ["rx-all-own-communities"],
        }

        policy_bgp_import_transit_template: dict[str, typing.Any] = copy.deepcopy(policy_bgp_import_peer)
        policy_bgp_import_transit_template["description"] = "simple default import policy for transits"
        policy_bgp_import_transit_template["entry"][40]["action"]["community"] = {
            "add": ["rx-origin-transit"],
            "remove": ["rx-all-own-communities"],
        }
        policy_bgp_import_transit_template["entry"][50]["action"]["community"] = {
            "add": ["rx-origin-transit"],
            "remove": ["rx-all-own-communities"],
        }
        policy_bgp_import_transit_template["entry"][60] = {
            "description": "import high pref prefixes with high pref",
            "from": {
                "prefix-list": ["@prefix-list@"]
            },
            "action": {
                "action-type": "accept",
                "local-preference": 120,
                "community": {
                    "add": ["rx-origin-transit"],
                    "remove": ["rx-all-own-communities"],
                }
            }
        }
        policy_bgp_import_transit_template["default-action"]["community"] = {
            "add": ["rx-origin-transit"],
            "remove": ["rx-all-own-communities"],
        }

        policy_bgp_import_peer_template: dict[str, typing.Any] = {
            "description": "import policy template for peers with IRR filtering",
            "entry": {
                10: entry_reject_too_small,
                20: entry_reject_bogons,
                30: entry_reject_peering_lans,
                40: {
                    "from": {
                        "prefix-list": ["@prefix-list@"],
                        "community": {
                            "name": "gshut"
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "local-preference": 0,
                        "community": {
                            "add": ["rx-origin-peers"],
                            "remove": ["rx-all-own-communities"],
                        }
                    }
                },
                50: {
                    "from": {
                        "prefix-list": ["@prefix-list@"],
                        "community": {
                            "name": "no-export"
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "local-preference": 90,
                        "community": {
                            "add": ["rx-origin-peers"],
                            "remove": ["rx-all-own-communities"],
                        }
                    }
                },
                60: {
                    "from": {
                        "prefix-list": ["@prefix-list@"],
                    },
                    "action": {
                        "action-type": "accept",
                        "community": {
                            "add": ["rx-origin-peers"],
                            "remove": ["rx-all-own-communities"],
                        }
                    }
                },
            },
            "default-action": {
                "action-type": "reject"
            }
        }

        policy_bgp_import_private_peer_template: dict[str, typing.Any] = copy.deepcopy(policy_bgp_import_peer_template)
        policy_bgp_import_private_peer_template["description"] = \
            "import policy template for private peers with IRR filtering"
        policy_bgp_import_private_peer_template["entry"][40]["action"]["community"] = {
            "add": ["rx-origin-privatepeers"],
            "remove": ["rx-all-own-communities"],
        }
        policy_bgp_import_private_peer_template["entry"][50]["action"]["community"] = {
            "add": ["rx-origin-privatepeers"],
            "remove": ["rx-all-own-communities"],
        }
        policy_bgp_import_private_peer_template["entry"][60]["action"]["community"] = {
            "add": ["rx-origin-privatepeers"],
            "remove": ["rx-all-own-communities"],
        }

        policy_bgp_export_peer_steering_communities_template: dict[str, typing.Any] = {
            "description": "export policy template for peers with steering communities",
            "entry": {
                10: entry_reject_too_small,
                20: entry_reject_bogons,
                30: entry_reject_peering_lans,
                40: entry_reject_ddos_routes,
                50: {
                    "description": "permit route-injection",
                    "from": {
                        "prefix-list": ["rx-bgp-announce"],
                        "protocol": {
                            "name": ["static"]
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "origin": "igp",
                        "community": {
                            "add": ["rx-origin-local", "@steering-community@"],
                            "remove": ["rx-steering-communities-and-route-targets"],
                        }
                    }
                },
                60: {
                    "description": "permit local routes",
                    "from": {
                        "community": {
                            "name": "rx-origin-local"
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "community": {
                            "add": ["@steering-community@"],
                            "remove": ["rx-steering-communities-and-route-targets"],
                        }
                    }
                },
                70: {
                    "description": "permit customer routes",
                    "from": {
                        "community": {
                            "name": "rx-origin-customers"
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "community": {
                            "add": ["@steering-community@"],
                            "remove": ["rx-steering-communities-and-route-targets"],
                        }
                    }
                },
            },
            "default-action": {
                "action-type": "reject"
            }
        }

        policy_bgp_import_customer_template: dict[str, typing.Any] = {
            "description": "transit customer import template",
            "entry": {
                10: {
                    "from": {
                        "as-path": {
                            "group": "@aspath-group@"
                        },
                        "prefix-list": ["@prefix-list@"],
                        "community": {
                            "name": "gshut"
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "local-preference": 0,
                        "community": {
                            "add": ["rx-origin-customers"],
                            "remove": ["@stripped-community@"],
                        }
                    }
                },
                20: {
                    "from": {
                        "as-path": {
                            "group": "@aspath-group@"
                        },
                        "prefix-list": ["@prefix-list@"],
                        "community": {
                            "name": "no-export"
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "local-preference": 90,
                        "community": {
                            "add": ["rx-origin-customers"],
                            "remove": ["@stripped-community@"],
                        }
                    }
                },
                30: {
                    "from": {
                        "as-path": {
                            "group": "@aspath-group@"
                        },
                        "prefix-list": ["@prefix-list@"],
                    },
                    "action": {
                        "action-type": "accept",
                        "community": {
                            "add": ["rx-origin-customers"],
                            "remove": ["@stripped-community@"],
                        }
                    }
                },
            },
            "default-action": {
                "action-type": "reject",
            }
        }

        policy_bgp_export_customer: dict[str, typing.Any] = {
            "description": "simple default export policy for customers",
            "entry": {
                10: entry_reject_too_small,
                20: entry_reject_bogons,
                30: entry_reject_peering_lans,
                # explicitly skip 40 (reject DDoS protected routes) for customers in case that they are single-homed
                50: entry_permit_route_injection,
                60: entry_permit_local_routes,
                70: entry_permit_customer_routes,
                80: {
                    "description": "permit peer routes",
                    "from": {
                        "community": {
                            "name": "rx-origin-peers"
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "community": {
                            "remove": ["rx-steering-communities-and-route-targets"],
                        }
                    }
                },
                90: {
                    "description": "permit privatepeer routes",
                    "from": {
                        "community": {
                            "name": "rx-origin-privatepeers"
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "community": {
                            "remove": ["rx-steering-communities-and-route-targets"],
                        }
                    }
                },
                100: {
                    "description": "permit transit routes",
                    "from": {
                        "community": {
                            "name": "rx-origin-transit"
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "community": {
                            "remove": ["rx-steering-communities-and-route-targets"],
                        }
                    }
                },
            },
            "default-action": {
                "action-type": "reject"
            }
        }

        policy_vrf_export_6000000: dict[str, typing.Any] = {
            "description": "internet VPRN vrf-export policy",
            "entry": {
                10: {
                    "description": "permit direct connected routes",
                    "from": {
                        "protocol": {
                            "name": ["direct"]
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "community": {
                            "add": ["rt-64600-54321"]
                        }
                    }
                },
                20: {
                    "description": "permit route-injection",
                    "from": {
                        "prefix-list": ["rx-bgp-announce"],
                        "protocol": {
                            "name": ["static"]
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "origin": "igp",
                        "community": {
                            "add": ["rx-origin-local", "rt-64600-54321"]
                        }
                    }
                },
                30: {
                    "description": "permit default route to separate route-target",
                    "from": {
                        "prefix-list": ["default-route"],
                        "protocol": {
                            "name": ["static"]
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "origin": "igp",
                        "community": {
                            "add": ["rt-64600-54322"]
                        }
                    }
                },
                40: {
                    "description": "permit static routes",
                    "from": {
                        "protocol": {
                            "name": ["static"]
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "community": {
                            "add": ["rt-64600-54321"]
                        }
                    }
                },
                50: {
                    "description": "permit eBGP routes",
                    "from": {
                        "path-type": "ebgp",
                        "protocol": {
                            "name": ["bgp"]
                        }
                    },
                    "action": {
                        "action-type": "accept",
                        "community": {
                            "add": ["rt-64600-54321"]
                        }
                    }
                }
            },
            "default-action": {
                "action-type": "reject",
            }
        }

        group = {
            "policy-options": {
                "community": communities,
                "prefix-list": prefix_lists,
                "policy-statement": {
                    "accept-all": policy_accept_all,
                    "drop-all": policy_drop_all,
                    "bgp-import-peer": policy_bgp_import_peer,
                    "bgp-import-peer-template": policy_bgp_import_peer_template,
                    "bgp-import-private-peer": policy_bgp_import_private_peer,
                    "bgp-import-private-peer-template": policy_bgp_import_private_peer_template,
                    "bgp-import-customer-template": policy_bgp_import_customer_template,
                    "bgp-import-transit-template": policy_bgp_import_transit_template,
                    "bgp-export-peer": policy_bgp_export_peer,
                    "bgp-export-peer-steering-communities-template": policy_bgp_export_peer_steering_communities_template,
                    "bgp-export-customer": policy_bgp_export_customer,
                    "bgp-export-peer-path-prepend": policy_bgp_export_peer_path_prepend,
                    "vrf-export-6000000": policy_vrf_export_6000000,
                }
            }
        }

        connection.candidate.set(f'/configure/groups/group[name="{config_group}"]', group, method="replace",
                                 commit=False)
