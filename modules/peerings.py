import ipaddress
import typing

import requests
from pysros.management import Connection

from lib.pysros import get_oper_system_name
from lib.validation import safe_get
from ._base_module import BaseModule
from .policies import (
    generate_bgp_import_peer_policy,
    generate_bgp_import_private_peer_policy,
    generate_bgp_import_transit_policy,
    generate_bgp_import_customer_policy,
    generate_bgp_import_customer_policy_soft_community_restrictions,
    generate_bgp_export_peer_steering_communities_policy
)


def check_for_tag(data: dict, tag_slug: str):
    tags = safe_get(data, "tags")

    if tags:
        for tag in tags:
            if tag["slug"] == tag_slug:
                return True
    return False


class PeeringsModule(BaseModule):
    def __init__(self) -> None:
        super().__init__()
        self.peering_manager_url = ""
        self.peering_manager_request_headers = {}
        self.deploy_irr_filters = False
        self.as_data_cache = {}
        self.irr_filter_as_ids = set()
        self.steering_community_as_ids = set()

    def get_as_data(self, as_id: int) -> dict[str, typing.Any]:
        if as_id in self.as_data_cache:
            return self.as_data_cache[as_id]

        r = requests.get(
            f"{self.peering_manager_url}/api/peering/autonomous-systems/{as_id}/",
            headers=self.peering_manager_request_headers,
        )
        as_data = r.json()

        self.as_data_cache[as_id] = as_data

        return as_data

    def check_irr_filters_excluded_for_as(self, as_id: int) -> bool:
        as_data = self.get_as_data(as_id)

        if check_for_tag(as_data, "no-irr-filter"):
            # skip ASes that are excluded by tag in peering-manager
            return True

        if safe_get(as_data, "prefixes"):
            sum_len = len(as_data["prefixes"]["ipv4"]) + len(as_data["prefixes"]["ipv6"])
            if sum_len == 0:
                # sanity check: raise exception for ASes with 0 prefixes in total
                asn = as_data["asn"]
                self.raise_exception(f"Would generate empty IRR filter for AS{asn}, aborting.")

        return False

    def check_is_ddos_protection_customer_for_as(self, as_id: int) -> bool:
        as_data = self.get_as_data(as_id)

        return check_for_tag(as_data, "ddos-protection-customer")

    def generate_prefix_list_for_as(self, as_id: int) -> dict:
        as_data = self.get_as_data(as_id)

        result = dict()

        if self.check_irr_filters_excluded_for_as(as_id):
            return result

        prefixes = safe_get(as_data, "prefixes")

        if not prefixes:
            return result

        prefixes_ipv4 = safe_get(as_data, "prefixes", "ipv4")
        prefixes_ipv6 = safe_get(as_data, "prefixes", "ipv6")

        if not prefixes_ipv4:
            prefixes_ipv4 = []

        if not prefixes_ipv6:
            prefixes_ipv6 = []

        combined_prefixes = prefixes_ipv4 + prefixes_ipv6

        for prefix in combined_prefixes:
            prefix_split = prefix["prefix"].split("/")
            prefix_mask = int(prefix_split[1])
            version = ipaddress.ip_address(prefix_split[0]).version

            if version == 4 and prefix_mask > 24:
                continue
            if version == 6 and prefix_mask > 48:
                continue

            if prefix["exact"]:
                result[(prefix["prefix"], "exact")] = {}
            else:
                greater_equal = safe_get(prefix, "greater-equal")
                start_length = greater_equal if greater_equal else prefix_mask
                end_length = prefix["less-equal"]
                result[(prefix["prefix"], "range")] = {
                    "start-length": start_length,
                    "end-length": end_length,
                }

        return result

    def validate_config(self) -> None:
        if not safe_get(self.secrets_config, "peering_manager_url"):
            self.raise_exception("The peerings module requires the peering manager URL in 'peering_manager_url' "
                                 "in the secrets config.")
        if not safe_get(self.secrets_config, "peering_manager_api_token"):
            self.raise_exception("The peerings module requires the peering manager API token "
                                 "in 'peering_manager_api_token' in the secrets config.")

        self.peering_manager_url = safe_get(self.secrets_config, "peering_manager_url")
        self.peering_manager_request_headers = {
            "Authorization": "Token " + safe_get(self.secrets_config, "peering_manager_api_token"),
        }

        r = requests.get(f"{self.peering_manager_url}/api/status", headers=self.peering_manager_request_headers)
        if r.status_code != 200:
            self.raise_exception("Failed to communicate with peering manager, maybe the API token is wrong?")

        self.deploy_irr_filters = bool(safe_get(self.config, "deploy_irr_filters"))

    def run(self, connection: Connection) -> None:
        config_group = "auto_peerings"

        system_name = get_oper_system_name(connection)

        r = requests.get(f"{self.peering_manager_url}/api/devices/routers/?limit=0",
                         headers=self.peering_manager_request_headers)
        routers = r.json()["results"]

        router_id = -1
        for router in routers:
            if router["name"] == system_name:
                router_id = router["id"]
                break

        if router_id == -1:
            self.raise_exception(f"Cannot find local router '{system_name}' in peering manager!")

        r = requests.get(f"{self.peering_manager_url}/api/devices/routers/{router_id}",
                         headers=self.peering_manager_request_headers)
        router = r.json()

        r = requests.get(
            f"{self.peering_manager_url}/api/peering/direct-peering-sessions/?router_id={router_id}&limit=0",
            headers=self.peering_manager_request_headers
        )
        direct_peerings = r.json()["results"]
        transits = [x for x in direct_peerings if x["relationship"]["slug"] == "transit-provider"]
        pnis = [x for x in direct_peerings if x["relationship"]["slug"] == "pni"]
        customers = [x for x in direct_peerings if x["relationship"]["slug"] == "transit-customer"]

        r = requests.get(
            f"{self.peering_manager_url}/api/net/connections/?router_id={router_id}&limit=0",
            headers=self.peering_manager_request_headers
        )
        ixp_connections = r.json()["results"]
        ixp_ids = [x["internet_exchange_point"]["id"] for x in ixp_connections]

        ixps = {}
        ixp_peerings = []

        for ixp_id in ixp_ids:
            r = requests.get(
                f"{self.peering_manager_url}/api/peering/internet-exchanges/{ixp_id}/",
                headers=self.peering_manager_request_headers,
            )
            ixp = r.json()
            ixps[ixp_id] = ixp

            r = requests.get(
                f"{self.peering_manager_url}/api/peering/internet-exchange-peering-sessions/?internet_exchange_id={ixp_id}&limit=0",
                headers=self.peering_manager_request_headers,
            )
            specific_ixp_peerings = r.json()["results"]
            extended_ixp_peerings = []
            for peering in specific_ixp_peerings:
                # needed later for ixp resolution for ixp-peerings
                peering["ixp_id"] = ixp_id
                extended_ixp_peerings.append(peering)
            ixp_peerings = ixp_peerings + extended_ixp_peerings

        bgp: dict[str, typing.Any] = {
            "admin-state": "enable",
            "best-path-selection": {
                "origin-invalid-unusable": True,
            },
            "group": {},
            "neighbor": {},
        }

        # Group definitions
        ## Transit
        for transit in transits:
            asn = transit['autonomous_system']['asn']
            as_id = transit['autonomous_system']['id']
            key = f"Transit-AS{asn}"
            if key in bgp["group"]:
                continue

            as_data = self.get_as_data(as_id)
            name = as_data["description"] if safe_get(as_data, "description") else as_data["name"]

            bgp["group"][key] = {
                "description": f"Transit {name}",
                "local-preference": 100,
                "advertise-inactive": True,
                "remove-private": {},
                "origin-validation": {
                    "ipv4": True,
                    "ipv6": True,
                },
                "import": {},
                "export": {},
            }

            if router["status"]["value"] == "maintenance":
                bgp["group"][key]["import"]["policy"] = ["drop-all"]
                bgp["group"][key]["export"]["policy"] = ["drop-all"]
            else:
                bgp["group"][key]["import"]["policy"] = [f"bgp-import-transit-AS{asn}"]
                bgp["group"][key]["export"]["policy"] = ["bgp-export-peer"]

        ## Private-Peerings
        if pnis:
            bgp["group"]["Private-Peering"] = {
                "local-preference": 115,
                "advertise-inactive": True,
                "remove-private": {},
                "origin-validation": {
                    "ipv4": True,
                    "ipv6": True,
                },
                "import": {},
                "export": {},
            }

            if router["status"]["value"] == "maintenance":
                bgp["group"]["Private-Peering"]["import"]["policy"] = ["drop-all"]
                bgp["group"]["Private-Peering"]["export"]["policy"] = ["drop-all"]
            else:
                bgp["group"]["Private-Peering"]["import"]["policy"] = ["bgp-import-private-peer"]
                bgp["group"]["Private-Peering"]["export"]["policy"] = ["bgp-export-peer"]

        ## Transit-Customers
        if customers:
            bgp["group"]["Transit-Customers"] = {
                "local-preference": 120,
                "advertise-inactive": True,
                "remove-private": {},
                "export": {},
            }

            if router["status"]["value"] == "maintenance":
                bgp["group"]["Transit-Customers"]["import"] = {}
                bgp["group"]["Transit-Customers"]["import"]["policy"] = ["drop-all"]
                bgp["group"]["Transit-Customers"]["export"]["policy"] = ["drop-all"]
            else:
                bgp["group"]["Transit-Customers"]["export"]["policy"] = ["bgp-export-customer"]

        ## IXPs
        for ixp_conn in ixp_connections:
            ixp_id = ixp_conn["internet_exchange_point"]["id"]
            ixp = ixps[ixp_id]
            description = ixp["description"] if safe_get(ixp, "description") else ixp["name"]

            key_v4 = f"{description} Peers IPv4"
            key_v6 = f"{description} Peers IPv6"

            if key_v4 in bgp["group"]:
                continue

            interface = ixp_conn["interface"]
            local_pref = ixp["config_context"]["ix_local_preference"] if \
                safe_get(ixp, "config_context", "ix_local_preference") else 110

            admin_state = "disable" if ixp["status"]["value"] == "disabled" else "enable"

            maintenance = (router["status"]["value"] == "maintenance" or ixp["status"]["value"] == "maintenance")

            general: dict[str, typing.Any] = {
                "admin-state": admin_state,
                "local-preference": local_pref,
                "next-hop-self": True,
                "local-address": interface,
                "advertise-inactive": True,
                "remove-private": {},
                "origin-validation": {
                    "ipv4": True,
                    "ipv6": True,
                },
                "damp-peer-oscillations": {},
                "import": {},
                "export": {},
            }

            if maintenance:
                general["import"]["policy"] = ["drop-all"]
                general["export"]["policy"] = ["drop-all"]
            else:
                general["import"]["policy"] = ["bgp-import-peer"]
                general["export"]["policy"] = ["bgp-export-peer"]

            group_v4 = {
                "family": {
                    "ipv4": True,
                },
                **general,
            }
            group_v6 = {
                "family": {
                    "ipv6": True,
                },
                **general,
            }

            bgp["group"][key_v4] = group_v4
            bgp["group"][key_v6] = group_v6

        # Neighbors
        ## Direct Peerings
        for peering in direct_peerings:
            ip = peering["ip_address"].split("/")[0]
            version = ipaddress.ip_address(ip).version
            relationship = peering["relationship"]["slug"]
            admin_state = "disable" if peering["status"]["value"] == "disabled" else "enable"
            as_id = peering["autonomous_system"]["id"]
            asn = peering["autonomous_system"]["asn"]
            as_data = self.get_as_data(as_id)
            description = as_data["description"] if safe_get(as_data, "description") else as_data["name"]

            if relationship == "transit-provider":
                group = f"Transit-AS{asn}"
                description = "Transit " + description
            elif relationship == "transit-customer":
                group = "Transit-Customers"
                service_number = safe_get(peering, "config_context", "service_number")
                if service_number:
                    description = f"{service_number} {description}"
                else:
                    description = "Transit-Customer " + description
            else:
                group = "Private-Peering"
                description = "Peering " + description

            bgp["neighbor"][ip] = {
                "admin-state": admin_state,
                "description": description,
                "peer-as": asn,
                "group": group,
                "family": {
                    f"ipv{version}": True,
                }
            }

            if safe_get(peering, "config_context", "peer_send_default"):
                bgp["neighbor"][ip]["send-default"] = {
                    f"ipv{version}": True,
                    "export-policy": "accept-all",
                }

            if check_for_tag(peering, "bfd"):
                bgp["neighbor"][ip]["bfd-liveness"] = True

            if safe_get(peering, "config_context", "peer_local_preference"):
                bgp["neighbor"][ip]["local-preference"] = peering["config_context"]["peer_local_preference"]

            if relationship != "transit-provider":
                bgp["neighbor"][ip]["prefix-limit"] = {
                    f"ipv{version}": {
                        "maximum": as_data[f"ipv{version}_max_prefixes"],
                        "threshold": 75,
                    }
                }

            if safe_get(peering, "password"):
                bgp["neighbor"][ip]["authentication-key"] = peering["password"]

            if peering["status"]["value"] == "maintenance":
                # explicitly set drop-all on session maintenance
                bgp["neighbor"][ip]["import"] = {
                    "policy": ["drop-all"]
                }
                bgp["neighbor"][ip]["export"] = {
                    "policy": ["drop-all"]
                }
            elif router["status"]["value"] != "maintenance":
                # set policies of there is no router maintenance
                if peering["import_routing_policies"]:
                    bgp["neighbor"][ip]["import"] = {
                        "policy": [x["name"] for x in peering["import_routing_policies"]]
                    }
                elif relationship == "transit-customer":
                    # set customer import policy if not stated otherwise
                    bgp["neighbor"][ip]["import"] = {
                        "policy": [f"bgp-import-customer-AS{asn}"]
                    }
                elif (relationship == "pni" and self.deploy_irr_filters
                      and not self.check_irr_filters_excluded_for_as(as_id)):
                    # set peer import policy if not stated otherwise
                    bgp["neighbor"][ip]["import"] = {
                        "policy": [f"bgp-import-peer-AS{asn}"]
                    }
                    self.irr_filter_as_ids.add((as_id, True))
                if peering["export_routing_policies"]:
                    bgp["neighbor"][ip]["export"] = {
                        "policy": [x["name"] for x in peering["export_routing_policies"]]
                    }
                elif check_for_tag(peering, "path-prepend"):
                    # set path prepend export policy if tag is set and no policy is explicitly defined
                    bgp["neighbor"][ip]["export"] = {
                        "policy": ["bgp-export-peer-path-prepend"]
                    }
                elif check_for_tag(as_data, "needs-steering-communities"):
                    # add steering community policy if requested by tag
                    bgp["neighbor"][ip]["export"] = {
                        "policy": [f"bgp-export-peer-steering-communities-AS{asn}"]
                    }
                    self.steering_community_as_ids.add(as_id)

        ## IXP Peerings
        for peering in ixp_peerings:
            ip = peering["ip_address"].split("/")[0]
            version = ipaddress.ip_address(ip).version
            admin_state = "disable" if peering["status"]["value"] == "disabled" else "enable"
            as_id = peering["autonomous_system"]["id"]
            asn = peering["autonomous_system"]["asn"]
            ixp_id = peering["ixp_id"]
            ixp = ixps[ixp_id]
            as_data = self.get_as_data(as_id)
            description = as_data["description"] if safe_get(as_data, "description") else as_data["name"]
            ixp_description = ixp["description"] if safe_get(ixp, "description") else ixp["name"]
            group = f"{ixp_description} Peers IPv{version}"

            bgp["neighbor"][ip] = {
                "admin-state": admin_state,
                "description": description,
                "peer-as": asn,
                "group": group,
                "prefix-limit": {
                    f"ipv{version}": {
                        "maximum": as_data[f"ipv{version}_max_prefixes"],
                        "threshold": 75,
                    }
                },
            }

            if safe_get(peering, "config_context", "peer_send_default"):
                bgp["neighbor"][ip]["send-default"] = {
                    f"ipv{version}": True,
                    "export-policy": "accept-all",
                }

            if check_for_tag(peering, "bfd"):
                bgp["neighbor"][ip]["bfd-liveness"] = True

            if safe_get(peering, "config_context", "peer_local_preference"):
                bgp["neighbor"][ip]["local-preference"] = peering["config_context"]["peer_local_preference"]

            if safe_get(peering, "password"):
                bgp["neighbor"][ip]["authentication-key"] = peering["password"]

            if peering["status"]["value"] == "maintenance":
                # explicitly set drop-all on session maintenance
                bgp["neighbor"][ip]["import"] = {
                    "policy": ["drop-all"]
                }
                bgp["neighbor"][ip]["export"] = {
                    "policy": ["drop-all"]
                }
            elif router["status"]["value"] != "maintenance" and ixp["status"]["value"] != "maintenance":
                # set policies of there is no router or IXP maintenance
                if peering["import_routing_policies"]:
                    bgp["neighbor"][ip]["import"] = {
                        "policy": [x["name"] for x in peering["import_routing_policies"]]
                    }
                elif (self.deploy_irr_filters and not self.check_irr_filters_excluded_for_as(as_id)
                      and not peering["is_route_server"]):
                    # set peer import policy if not stated otherwise
                    bgp["neighbor"][ip]["import"] = {
                        "policy": [f"bgp-import-peer-AS{asn}"]
                    }
                    self.irr_filter_as_ids.add((as_id, False))
                if peering["export_routing_policies"]:
                    bgp["neighbor"][ip]["export"] = {
                        "policy": [x["name"] for x in peering["export_routing_policies"]]
                    }
                elif check_for_tag(peering, "path-prepend"):
                    # set path prepend export policy if tag is set and no policy is explicitly defined
                    bgp["neighbor"][ip]["export"] = {
                        "policy": [f"bgp-export-peer-path-prepend"]
                    }
                elif check_for_tag(as_data, "needs-steering-communities"):
                    # add steering community policy if requested by tag
                    bgp["neighbor"][ip]["export"] = {
                        "policy": [f"bgp-export-peer-steering-communities-AS{asn}"]
                    }
                    self.steering_community_as_ids.add(as_id)

        # Sanity checks
        if not bgp["group"]:
            self.raise_exception("Generated empty groups config, aborting!")

        if not bgp["neighbor"]:
            self.raise_exception("Generated empty neighbors config, aborting!")

        group = {
            "service": {
                "vprn": {
                    "6000000": {
                        "bgp": bgp
                    }
                }
            }
        }

        policy_options = {}

        if transits:
            policy_options["prefix-list"] = {}
            policy_options["policy-statement"] = {}
            for transit in transits:
                asn = transit['autonomous_system']['asn']
                prefix_list_name = f"AS{asn}-highpref"
                statement_name = f"bgp-import-transit-AS{asn}"
                policy_options["prefix-list"][prefix_list_name] = {}
                policy_options["policy-statement"][statement_name] = generate_bgp_import_transit_policy(
                    prefix_list_name, asn
                )

        if customers:
            if not "prefix-list" in policy_options:
                policy_options["prefix-list"] = {}
            if not "policy-statement" in policy_options:
                policy_options["policy-statement"] = {}
            policy_options["as-path-group"] = {}
            for customer in customers:
                asn = customer['autonomous_system']['asn']
                as_id = customer['autonomous_system']['id']
                prefix_list_name = f"customer-AS{asn}-in"
                as_path_name = prefix_list_name
                statement_name = f"bgp-import-customer-AS{asn}"
                policy_options["as-path-group"][as_path_name] = {}
                policy_options["prefix-list"][prefix_list_name] = {}

                if self.check_is_ddos_protection_customer_for_as(as_id):
                    policy_options["policy-statement"][statement_name] = \
                        generate_bgp_import_customer_policy_soft_community_restrictions(
                            prefix_list_name, as_path_name, asn
                        )
                else:
                    policy_options["policy-statement"][statement_name] = generate_bgp_import_customer_policy(
                        prefix_list_name, as_path_name, asn
                    )

        if self.steering_community_as_ids:
            if not "policy-statement" in policy_options:
                policy_options["policy-statement"] = {}
            policy_options["community"] = {}
            for steering_community_as_id in self.steering_community_as_ids:
                as_data = self.get_as_data(steering_community_as_id)
                asn = as_data["asn"]
                statement_name = f"bgp-export-peer-steering-communities-AS{asn}"
                community_name = f"steering-communities-AS{asn}"

                policy_options["community"][community_name] = {}
                policy_options["policy-statement"][statement_name] = \
                    generate_bgp_export_peer_steering_communities_policy(
                        community_name,
                        asn
                    )

        if self.deploy_irr_filters and self.irr_filter_as_ids:
            if not "prefix-list" in policy_options:
                policy_options["prefix-list"] = {}
            if not "policy-statement" in policy_options:
                policy_options["policy-statement"] = {}
            for (as_id, private_peering) in self.irr_filter_as_ids:
                as_data = self.get_as_data(as_id)
                asn = as_data["asn"]
                prefix_list = self.generate_prefix_list_for_as(as_id)
                list_name = f"peer-AS{asn}-in"
                statement_name = f"bgp-import-peer-AS{asn}"
                policy_options["prefix-list"][list_name] = {
                    "prefix": prefix_list,
                }
                if private_peering:
                    policy_options["policy-statement"][statement_name] = generate_bgp_import_private_peer_policy(
                        list_name, asn
                    )
                else:
                    policy_options["policy-statement"][statement_name] = generate_bgp_import_peer_policy(list_name, asn)

        if policy_options:
            group["policy-options"] = policy_options

        connection.candidate.set(f'/configure/groups/group[name="{config_group}"]', group, method="replace",
                                 commit=False)
