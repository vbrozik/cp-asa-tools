#!/usr/bin/python3
"""Process static routing information from Cisco ASA configuration."""

from __future__ import annotations

import argparse
import contextlib
import sys
import enum
import re

from typing import Any, Optional, Iterable, List, TextIO
from pydantic import BaseModel, Field


# --- regexes
RE_IPV4 = r'(?:\d{1,3}\.){3}\d{1,3}'
RE_ASA_IDF = r'[A-Za-z][-A-Za-z0-9_]*'  # ASA identifier


class ASALineCtx(enum.Enum):
    """Indicate ASA configuration file context."""

    top = enum.auto()
    interface = enum.auto()


class BaseModelExt(BaseModel):
    """Extend BaseModel."""

    @classmethod
    def parse_iterable(cls, values: Iterable):  # FIXME return type
        """Create object from fields given positionally in an iterable."""
        return cls.parse_obj(dict(zip(cls.__fields__, values)))


class StaticRoute(BaseModelExt):
    """Store ASA static route definition."""

    if_name: str = Field(regex=f'^{RE_ASA_IDF}$')
    dest_ip: str = Field(regex=f'^{RE_IPV4}$')
    mask: str = Field(regex=f'^{RE_IPV4}$')
    gateway_ip: str = Field(regex=f'^{RE_IPV4}$')
    distance: Optional[int] = Field(ge=1, le=1)     # too strict


class Interface(BaseModelExt):
    """Store ASA interface definition."""

    sys_name: str = Field(regex=f'^{RE_ASA_IDF}$')
    name: str = Field(regex=f'^{RE_ASA_IDF}$')
    ip_addr: str = Field(regex=f'^{RE_IPV4}$')
    mask: str = Field(regex=f'^{RE_IPV4}$')
    standby_ip: Optional[str] = Field(default=None, regex=f'^{RE_IPV4}$')
    security_level: Optional[int] = Field(default=None, ge=0, le=100)
    vlan_id: Optional[int] = None


class AsaConfig(BaseModelExt):
    """Store ASA configuration."""

    static_routes: List[StaticRoute] = Field(default_factory=list)
    interfaces: List[Interface] = Field(default_factory=list)


def read_asa_config(lines: Iterable[str]) -> AsaConfig:
    """Read ASA configuration file."""
    def set_key_or_fail(d: dict, key: Any, value: Any):
        assert key not in d, f"Key {key} already exist in the dictionary."
        d[key] = value

    asaconfig = AsaConfig()
    ctx = ASALineCtx.top
    for line in lines:
        words = line.split()
        if not words:
            continue
        word0 = words.pop(0)
        if ctx == ASALineCtx.top:
            if word0 == 'route':
                asaconfig.static_routes.append(
                                        StaticRoute.parse_iterable(words))
            elif word0 == 'interface':
                ctx = ASALineCtx.interface
                interface: dict[str, str] = {'sys_name': words[0]}
                if match := re.fullmatch(r'Vlan(?P<vlan_id>[0-9]+)', words[0]):
                    set_key_or_fail(
                                interface, 'vlan_id', match.group('vlan_id'))
        elif ctx == ASALineCtx.interface:
            if word0 == '!':
                asaconfig.interfaces.append(Interface.parse_obj(interface))
                ctx = ASALineCtx.top
            elif word0 == 'nameif':
                set_key_or_fail(interface, 'name', words[0])
            elif word0 == 'security-level':
                set_key_or_fail(interface, 'security_level', words[0])
            elif word0 == 'ip' and words[0] == 'address':
                set_key_or_fail(interface, 'ip_addr', words[1])
                set_key_or_fail(interface, 'mask', words[2])
                if words[3] == 'standby':
                    set_key_or_fail(interface, 'standby_ip', words[4])
            else:
                assert False, (
                        f"Unexpected keyword {word0} in interface context")
    return asaconfig


def write_vsx_config(
            asaconfig: AsaConfig, args: argparse.Namespace,
            out_file: TextIO = sys.stdout):
    """Generate configuration commands for vsx_provisioning_tool."""
    print("transaction begin", file=out_file)
    print(f"add vd name {args.dst_vs} vsx {args.ds_vsx}", file=out_file)
    vd_spec = "" if True else f"vd {args.dst_vs} "
    for intf in asaconfig.interfaces:
        print(
                f"add interface {vd_spec}"
                f"name {args.phys_if}.{intf.vlan_id} "
                f"ip {intf.ip_addr} netmask {intf.mask} "
                f"mtu {args.if_mtu}",
                file=out_file)
    for sroute in asaconfig.static_routes:
        print(
                f"add route {vd_spec}"
                f"destination {sroute.dest_ip} netmask {sroute.mask} "
                f"next_hop {sroute.gateway_ip}",
                file=out_file)
    print("transaction end", file=out_file)


def main():
    """Provide CLI interface."""
    # --- CLI interface
    parser = argparse.ArgumentParser()
    parser.add_argument(
            'in_file', nargs='?', type=argparse.FileType('r'),
            help="input ASA configuration file")
    parser.add_argument(
            'out_file', nargs='?', type=argparse.FileType('w'),
            help="output vsx_provisioning_tool commands")
    args = parser.parse_args()
    args.ds_vsx = 'lab_vsx'
    args.dst_vs = 'intervrf_01'
    args.phys_if = 'eth3'
    args.if_mtu = 4096
    # --- file input
    with contextlib.ExitStack() as file_stack:
        asaconfig = read_asa_config(
                    file_stack.enter_context(args.in_file) if args.in_file
                    else sys.stdin)
    # --- file output
    with contextlib.ExitStack() as file_stack:
        out_file = (
                    file_stack.enter_context(args.out_file) if args.out_file
                    else sys.stdout)
        write_vsx_config(asaconfig, args, out_file)


if __name__ == '__main__':
    main()
