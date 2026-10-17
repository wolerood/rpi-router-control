import json
import os
import subprocess

from access_policy import normalize_mac


NFT_BINARY = os.environ.get("RPI_ROUTER_NFT_BINARY", "/usr/sbin/nft")
NFT_FAMILY = "inet"
NFT_TABLE = "parental_control"
NFT_SET = "blocked_macs"


class FirewallError(RuntimeError):
    pass


def run_nft(args):
    result = subprocess.run(
        [NFT_BINARY, *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise FirewallError(detail)
    return result.stdout


def parse_blocked_macs(payload):
    data = json.loads(payload)
    blocked = set()

    for item in data.get("nftables", []):
        set_data = item.get("set")
        if not set_data:
            continue

        for element in set_data.get("elem", []):
            if isinstance(element, str):
                blocked.add(normalize_mac(element))

    return blocked


def get_blocked_macs():
    payload = run_nft([
        "-j",
        "list",
        "set",
        NFT_FAMILY,
        NFT_TABLE,
        NFT_SET,
    ])
    return parse_blocked_macs(payload)


def block_mac(mac):
    mac = normalize_mac(mac)
    run_nft([
        "add",
        "element",
        NFT_FAMILY,
        NFT_TABLE,
        NFT_SET,
        "{",
        mac,
        "}",
    ])


def allow_mac(mac):
    mac = normalize_mac(mac)
    run_nft([
        "delete",
        "element",
        NFT_FAMILY,
        NFT_TABLE,
        NFT_SET,
        "{",
        mac,
        "}",
    ])
