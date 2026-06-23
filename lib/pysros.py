import re
from dataclasses import dataclass
from typing import Self

from pysros.management import Connection


class VersionParsingException(Exception):
    pass


@dataclass
class SROSVersion:
    major: int
    minor: int
    release: int

    @classmethod
    def from_str(cls, version_string: str) -> Self:
        match = re.search(r"(\w-)?(\d+)\.(\d+)\.R(\d+)", version_string)
        if not match:
            raise VersionParsingException("Failed to parse received SR-OS version!")

        major = int(match.group(2))
        minor = int(match.group(3))
        release = int(match.group(4))

        return cls(major, minor, release)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.R{self.release}"


def connect(host: str, username: str, password: str,
            port: int = 830, timeout: int = 300, hostkey_verify: bool = True) -> Connection:
    # instantiate Connection manually for ssh_config support
    conn = Connection(host=host,
                      username=username,
                      password=password,
                      port=port,
                      device_params={'name': 'sros'},
                      manager_params={'timeout': timeout},
                      nc_params={'capabilities': ['urn:nokia.com:nc:pysros:pc']},
                      hostkey_verify=hostkey_verify,
                      yang_directory=None,
                      rebuild=False,
                      ssh_config=True,
                      allow_agent=True,
                      )
    return conn


# utility functions
def get_oper_system_name(connection: Connection) -> str:
    system_state = connection.running.get("/state/system")
    return str(system_state["oper-name"])


def get_device_type(connection: Connection) -> str:
    system_state = connection.running.get("/state/system")
    return str(system_state["platform"])


def get_platform_type(connection: Connection) -> str:
    chassis_state = connection.running.get("/state/chassis[chassis-class='router'][chassis-number='1']/hardware-data")
    return str(chassis_state['equipped-platform-type'])


def get_version(connection: Connection) -> SROSVersion:
    version_state = connection.running.get("/state/system/version")
    return SROSVersion.from_str(str(version_state["version-number"]))
