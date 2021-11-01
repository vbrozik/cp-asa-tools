#!/usr/bin/python3
"""Convert routing information from Cisco ASA configuration to VSX.

Processed and converted data:
    * VLAN interfaces
    * static routes
"""

from __future__ import annotations

import argparse
import contextlib
import sys
import enum
import re
import os

from typing import IO, Any, Optional, Iterable, List, TextIO
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


# --- parsed configuration storage

class Interface(BaseModelExt):
    """Store ASA interface definition."""

    sys_name: str = Field(regex=fr'^{RE_ASA_IDF}$')
    name: str = Field(regex=fr'^{RE_ASA_IDF}$')
    ip_addr: str = Field(regex=fr'^{RE_IPV4}$')
    mask: str = Field(regex=fr'^{RE_IPV4}$')
    standby_ip: Optional[str] = Field(default=None, regex=f'^{RE_IPV4}$')
    security_level: Optional[int] = Field(default=None, ge=0, le=100)
    vlan_id: Optional[int] = None


class StaticRoute(BaseModelExt):
    """Store ASA static route definition."""

    if_name: str = Field(regex=fr'^{RE_ASA_IDF}$')
    dest_ip: str = Field(regex=fr'^{RE_IPV4}$')
    mask: str = Field(regex=fr'^{RE_IPV4}$')
    gateway_ip: str = Field(regex=fr'^{RE_IPV4}$')
    distance: Optional[int] = Field(ge=1, le=1)     # strict for certain config


class PrefixList(BaseModelExt):
    """Store ASA prefix list item.

    https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/pr-pz-commands.html#wp3011918550
    """

    name: str = Field(regex=fr'^{RE_ASA_IDF}$')
    action: str = Field(regex=r'^permit|deny$')
    network: str = Field(regex=fr'^{RE_IPV4}$')
    masklen: int = Field(ge=0, le=32)
    min_prefix_len: Optional[int] = Field(default=None, ge=1, le=32)
    max_prefix_len: Optional[int] = Field(default=None, ge=1, le=32)
    seq: Optional[int] = None


class AsaConfig(BaseModelExt):
    """Store ASA configuration."""

    interfaces: List[Interface] = Field(default_factory=list)
    static_routes: List[StaticRoute] = Field(default_factory=list)
    prefix_lists: List[PrefixList] = Field(default_factory=list)


# --- functions

def parse_prefix_list(words: list[str]) -> Optional[PrefixList]:
    """Parse single line of ASA prefix list to PrefixList object.

    The `prefix-list` keyword is removed already. The `words` list
    is destroyed by this function.
    """
    # print(words)
    prefix_list_d = {'name': words.pop(0)}
    if words[0] == 'seq':
        prefix_list_d['seq'] = words[1]
        del words[:2]
    if (action := words.pop(0)) == 'description':
        return None     # 'description' not implemented
    prefix_list_d['action'] = action
    if not (match := re.fullmatch(
                        fr"(?P<network>{RE_IPV4})/(?P<masklen>[1-3]?[0-9])",
                        words.pop(0))):
        # print(words)
        # print(prefix_list_d)
        raise ValueError
    prefix_list_d['network'] = match.group('network')
    prefix_list_d['masklen'] = match.group('masklen')
    while words:
        op = words.pop(0)
        if op == 'le' and 'max_prefix_len' not in prefix_list_d:
            prefix_list_d['max_prefix_len'] = words.pop(0)
        elif op == 'ge' and 'min_prefix_len' not in prefix_list_d:
            prefix_list_d['min_prefix_len'] = words.pop(0)
        else:
            raise ValueError
    return PrefixList.parse_obj(prefix_list_d)


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
            elif word0 == 'prefix-list':
                if (prefix := parse_prefix_list(words)) is not None:
                    asaconfig.prefix_lists.append(prefix)
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


def write_vsx_provisioning_config(
            asaconfig: AsaConfig, args: argparse.Namespace,
            out_file: TextIO = sys.stdout):
    """Generate configuration commands for vsx_provisioning_tool."""
    print("transaction begin", file=out_file)
    print(f"add vd name {args.dst_vs} vsx {args.dst_vsx}", file=out_file)
    vd_spec = "" if True else f"vd {args.dst_vs} "
    for intf in asaconfig.interfaces:
        print(
                f"add interface {vd_spec}"
                f"name {args.phys_if}.{intf.vlan_id} "
                f"ip {intf.ip_addr} netmask {intf.mask} "
                f"mtu {args.if_mtu}",
                file=out_file)
    for sroute in asaconfig.static_routes:
        dest = ("default "
                if sroute.dest_ip == "0.0.0.0" and sroute.mask == "0.0.0.0"
                else f"{sroute.dest_ip} netmask {sroute.mask} ")
        print(
                f"add route {vd_spec}"
                f"destination {dest}"
                f"next_hop {sroute.gateway_ip}",
                file=out_file)
    print("transaction end", file=out_file)


def write_vsx_prefix_lists(
            asaconfig: AsaConfig, args: argparse.Namespace,
            out_file: TextIO = sys.stdout):
    """Generate clish commands for routing prefix lists."""
    if args.dst_vs is not None:
        print(f"set virtual system {args.dst_vs}", file=out_file)
    current_prefix_name: Optional[str] = None
    for prefix in asaconfig.prefix_lists:
        if prefix.name != current_prefix_name:
            print(f"#{'-'*38}", file=out_file)
            current_prefix_name = prefix.name
            seq_number = 0
        seq_number += 10
        subnets = (
            'all' if prefix.min_prefix_len or prefix.max_prefix_len
            else 'exact')
        print(
                f"set prefix-list {prefix.name} "
                f"sequence-number {seq_number} "
                f"prefix {prefix.network}/{prefix.masklen} "
                f"{subnets}",
                file=out_file)


def replace_fname_suffix(fname: str, new_suffix: str) -> str:
    """Replace file name suffix."""
    if not fname or fname == '-':
        return fname
    return os.path.splitext(fname)[0] + new_suffix


def open_to_stack(
        stack: contextlib.ExitStack, fname: str, mode: str = 'r') -> IO:
    """Open file if not '-' and add it to the ExitStack."""
    if not fname or fname == '-':
        return sys.stdout if 'w' in mode else sys.stdin
    return stack.enter_context(open(fname, mode))


def main():
    """Provide CLI interface."""
    # --- CLI interface
    parser = argparse.ArgumentParser()
    parser.add_argument(
            'in_file', nargs='?',
            help="input ASA configuration file")
    parser.add_argument(
            'out_dir', nargs='?',
            help="output directory")
    args = parser.parse_args()
    args.dst_vsx = 'lab_vsx'
    args.dst_vs = 'intervrf_01'
    args.phys_if = 'eth3'
    args.if_mtu = 4096
    args.out_vsx_prov_suffix = '_vsxprov.cfg'
    args.out_vsx_clish_suffix = '_clish.cfg'
    # --- file input
    with contextlib.ExitStack() as file_stack:
        asaconfig = read_asa_config(
                    open_to_stack(file_stack, args.in_file))
        file_stack.close()
    # --- file output
        write_vsx_provisioning_config(
                asaconfig, args,
                open_to_stack(file_stack, replace_fname_suffix(
                                args.in_file, args.out_vsx_prov_suffix), 'w'))
        file_stack.close()
        write_vsx_prefix_lists(
                asaconfig, args,
                open_to_stack(file_stack, replace_fname_suffix(
                                args.in_file, args.out_vsx_clish_suffix), 'w'))


if __name__ == '__main__':
    main()
