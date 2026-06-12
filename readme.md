# Modular Nokia SR OS automation

This repo is an example of our modular Nokia SR OS automation using the [pySROS](https://network.developer.nokia.com/static/sr/learn/pysros/latest/index.html) library from Nokia.
It contains all of our currently existing modules (some are slightly modified to censor sensitive information) to inspire you how you can build your own modules.

> [!IMPORTANT]
> This repository should just act as an example for you to build your own automation solution with it.
>
> The state of the example modules is just a snapshot from our production environment and changes to our environment may not be published to this repository.

## What can you do with this repository?

Use it to build your own modular automation! Take our modules as inspiration to build your own modules for your environment!

Read the technical details below to understand how it works and how you can use it to automate every aspect of your network with any sources of truth you can imagine.

## Motivation

We have built our own automation from scratch because we already had our network established for years now and already had business processes established that
relied on the current state of the network.

The problem with many of the monolithic automation solutions is that you have to automate everything at once and that you have to adjust all of your
business processes and your sources of truth to your automation solution.

We didn't want that. We wanted it the other way around: the automation should adjust to our existing business processes and we wanted to continue to use
our existing sources of truth.

Additionally, we want to be able to make manual overrides at any point and we want to understand everything the automation does on our routers.

Another aspect is the security: many of the existing solutions just have unrestricted access to all of your routers. What if there is a security issue with the
automation solution? Maybe an attacker can compromise all of your routers by compromising your automation solution.

So we wanted to be able to limit the permissions of an automation user for a module to the absolute minimum it needs to deploy its module and nothing else.

## Config Groups

Config groups are a feature of SR OS in Full-MD-Mode that basically enables the concept of modular automation in the first place.

With config groups, you can basically have as many configuration trees as you want besides the main configuration tree and then apply those additional trees
to the main configuration tree.

Here is a brief example:

Definition of our config group:
```
A:admin@bar# info groups group "example"
    system {
        name "foo"
        time {
            zone {
                standard {
                    name cet
                }
            }
            ntp {
                server 10.0.0.1 router-instance "base" {
                }
            }
        }
    }
```

Configuration in the main config tree:
```
A:admin@foo# info
    [...] # skipped some other config values
    system {
        apply-groups ["example"] # apply the config group
        name "foo" # also set a system name in the main config tree
        [...] # skipped some default config values
        time {
            ntp {
                apply-groups-exclude ["example"] # exclude the config group from the ntp subtree
            }
        }
    }
```

Resulting configuration of the main config tree:
```
A:admin@foo# info inheritance
    [...] # skipped some other config values
    system {
        apply-groups ["example"]
        name "foo" # name is taken from the main config tree because it is explicitly defined there
        [...] # skipped some default config values
        time {
            zone {
                standard {
                    ## inherited: from group "example"
                    name cet # timezone gets inherited from config group
                }
            }
            ntp {
                apply-groups-exclude ["example"]
                # ntp server is not inherited because it is excluded
            }
        }
    }
```

## Concept of the modular automation

With config groups, our concept of modular automation is the following:

- One module = one logically separated task = one config group
  - This directly solves the security issue: you can simply limit an automation user to its config group
  - Manual overrides work out of the box with config groups as shown above
- No automated modifications to the main config tree at all --> every config group is applied manually for full control
- Config groups should always be applied on the deepest possible level for each module for security reasons
- Each module can have a different source of truth (or even several at once), depending on its task
- Some modules may depend on another module
- Some modules may provide some helper functions for modules that depend on them

## Project structure

```
.
├── lib                   # contains library and helper functions
├── modules
│   ├── _base_module.py       # abstract base class for all modules
│   ├── admin_users.py        # admin users module
│   ├── base_config.py        # base configuration module
│   ├── block_lists.py        # IP ingress filter module
│   ├── emergency_admin.py    # emergency admin user module
│   ├── peerings.py           # peerings module (depends on the policies module)
│   └── policies.py           # policies module, provides helper functions for the peerings module
├── apply.py              # main script of the automation, executes the modules
├── config.yaml           # main configuration file, also contains abstract configuration for some modules
├── flake.nix             # Nix (https://nixos.org) flake for setting up an environment for development
├── flake.lock            # Lockfile for the Nix flake
├── requirements.txt      # Python requirements file for setting up a Python venv for development
├── secrets.example.yaml  # example configuration for secrets that are not tracked in the git repository
└── validate_config.py    # script that checks if all settings in the config.yaml have their expected values
```

## Usage instructions

The main script of the project is the [apply.py](./apply.py):

```
$ ./apply.py -h
usage: apply.py [-h] [-c CONFIG] [-s SECRETSCONFIG] [-m MODULES] [-u USER] [-p PASSWORD] [--askpass] [--commit] [--commit_yes] [--diff] target

SR OS NETCONF automation

positional arguments:
  target                Deployment target host

options:
  -h, --help            show this help message and exit
  -c, --config CONFIG   Path to the Config-File
  -s, --secretsconfig SECRETSCONFIG
                        Path to the secrets Config-File
  -m, --modules MODULES
                        Comma separated list of modules to run
  -u, --user USER       Username to use
  -p, --password PASSWORD
                        Password for the user
  --askpass             Ask for password
  --commit              Commit changes
  --commit_yes          Commit changes without asking
  --diff                Print diff
```

> [!NOTE]
> The parameters `user` and `password` both default to the value `admin` if not specified. If you want to use your SSH key, you can just omit the `password` and pySROS will try to
> use your SSH key according to your local SSH config. SSH agents are also supported.

Both configuration files default to the files in the repository relative to the script location.

You can use the [validate_config.py](./validate_config.py) script to ensure that all settings in the [config.yaml](./config.yaml) have their expected values. This is purely optional
and may help you if you have the repository checked out on a host that is shared with multiple admin users and to quickly check if someone has messed with the config file.

Additionally, the [config.yaml](./config.yaml) contains some settings that enforce that the [apply.py](./apply.py) can only be executed when the repository is up to date and unmodified.
You can disable those constraints in the `repo` settings in the [config.yaml](./config.yaml).

### Examples

Apply the module `peerings` on the router `router1.example.com` as the user `user1`, ask for the password of the user, print the diff, and ask if the changes should be committed:
```
$ ./apply -u user1 --askpass -m peerings router1.example.com --diff --commit
```

Apply the modules `admin_users` and `base_config` on the router `router1.example.com` using the default credentials `admin:admin`. Also show the diff, and ask if the changes should be committed:
```
$ ./apply -m admin_users,base_config router1.example.com --diff --commit
```

Apply the module `emergency_admin` on the router `router1.example.com` as the user `user1` using the SSH key specified in the local SSH config. Also show the diff, and ask if the changes should be committed:
```
$ ./apply -u user1 -m emergency_admin router1.example.com --diff --commit
```

### Prerequisites on SR OS routers

To use this automation solution on your routers, you have to be in Full-MD-Mode, enable NETCONF on your routers, and allow NETCONF for your user:

```
system {
    management-interface {
        configuration-mode model-driven
        netconf {
            listen {
                admin-state enable
            }
        }
    }
    security {
        user-params {
            local-user {
                user "admin" {
                    access {
                        netconf true
                    }
                }
            }
        }
    }
}
```

## Module structure

Each module is a subclass of the abstract base class `BaseModule` defined in [modules/_base_module.py](./modules/_base_module.py).

The `BaseModule` provides 3 methods that may be implemented by a module:

- `validate_config()`: Optional: Checks if the given module config in the [config.yaml](./config.yaml) is valid. Can also check the validity of the secret config. Raises an exception if the config is invalid.
- `run(connection: Connection)`:
    - Main entry point of the module
    - Gets a [pySROS](https://network.developer.nokia.com/static/sr/learn/pysros/latest/index.html) connection instance as a parameter
    - Populates the config group of the module and fully replaces it in each run
      - Note: the `set()` call to replace the config group must always be called with `commit=False` for the `--commit` CLI flag to work (otherwise it would instantly commit the changes)
- `post_run()`: Optional: Gets called after diff output and commit. Useful to print summaries of the module run.


## Adding new modules

To add a new module, you have to:
1. Create the module as a subclass of the `BaseModule` in the [modules](./modules) directory
2. Add the class of your module to the [__init__.py](./modules/__init__.py) in the [modules](./modules) directory
3. Add the class of your module to the `module_map` in the [apply.py](./apply.py) script

## Example modules

> [!NOTE]
> Those modules are from our production automation environment and only slightly modified to censor sensitive data. Those modules are written specifically for our
> environment and will most likely not work in your environment, but you can use them as inspiration or modify them so that they work in your environment :)

### [Admin-Users Module](./modules/admin_users.py)

Deploys accounts for human admin users and adds their SSH keys (if given). This module is tied to our environment, where we don't use the locally defined password
for a user and instead authenticate against a RADIUS server if password authentication is used.

But since SR OS requires a password to be locally defined if you want to define SSH keys for a user, a password is randomly generated for each user and never shown to the user.
The hash of the randomly generated passwords gets reused on every consecutive run to prevent unnecessary config diffs.

The users and their SSH keys are specified in the [config.yaml](./config.yaml).
Additionally, you can explicitly set a flag for a user to force the randomly generated password to be regenerated if you need that for some reason.

Points to apply in the main config tree:
```
/configure system security user-params apply-groups ["auto_admin_users"]
```

### [Base-Config Module](./modules/base_config.py)

This module simply contains some basic configuration settings that should be applied to all routers. There is no logic involved at all in this module, since all settings are basically hardcoded.

Points to apply in the main config tree:
```
/configure log apply-groups ["auto_base_config"]
/configure system security apply-groups ["auto_base_config"]
/configure system time apply-groups ["auto_base_config"]
```

## [IP-Ingress-Filters Module](./modules/block_lists.py)

Deploys IP ingress filters for all public-facing SAPs on our border routers (so every SAP for IXPs, transit connections or PNIs).

The contents of the filters are defined in the [config.yaml](./config.yaml) and contain bogon prefixes in this example. You may, for example, add prefixes of an attacker if you are getting
attacked by a DDoS or something like that.

Usage example of these filters (note: VPRN 6000000 is our internet VPRN, but you may use it on any SAP):
```
service {
    vprn "6000000" {
        interface "example" {
            sap 1/1/1 {
                ingress {
                    filter {
                        ip "INBOUND-CONTROL"
                        ipv6 "INBOUND-CONTROL"
                    }
                }
            }
        }
    }
}
```

## [Emergency-Admin Module](./modules/emergency_admin.py)

Randomly generates a password for the `admin` user and prints it afterwards to be stored in a password manager.

> [!NOTE]
> This module is disabled by default in the [config.yaml](./config.yaml) to prevent accidental overrides of the password.

> [!NOTE]
> Make sure to delete the password of the `admin` user in the main config tree first.

Points to apply in the main config tree:
```
/configure system security apply-groups ["auto_emergency_admin"]
```

## [Peerings Module](./modules/peerings.py)

Automatically configures all of our eBGP sessions to transit providers, transit customers, PNIs and IXPs based on [Peering-Manager](https://peering-manager.net/), our source of truth for all eBGP related things.

Depends on the `policies` module (shown next) to request some special policies for some peers and to ensure that some basic policies exist in any case.

> [!NOTE]
> This module also has the capability to generate IRR-based import filters for all peers using the Peering-Manager. It is currently disabled but can be enabled in the [config.yaml](./config.yaml).
>
> Please note that this feature currently skips IRR-filter-generation for ASes with >= 10k prefixes, since pySROS throws an error if you try to deploy prefix lists with more than ~10k entries.
> We don't know the reason for this error yet, but at least you can use the current state of the module to deploy IRR-based import filters for all ASes you peer with less than 10k prefixes.

Points to apply in the main config tree:
```
/configure service vprn "6000000" bgp apply-groups ["auto_peerings"]
/configure policy-options apply-groups ["auto_peerings"]
```

## [Policies Module](./modules/policies.py)

Generates nearly all policies, prefix lists and communities for our routers. Also provides helper functions for the `peerings` module to generate some template calls for template-policies.

Points to apply in the main config tree:
```
/configure policy-options apply-groups ["auto_policies"]
```
