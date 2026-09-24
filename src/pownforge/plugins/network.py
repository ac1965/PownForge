from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError, PluginExecution


def _scan_host(target: Target) -> str:
    """The bare host/IP nmap should scan: TARGET.address as-is for a `host`
    target, or the hostname portion of a `url` target's address (nmap can't
    parse a full "http://host:port" URL as a scan target)."""
    if target.kind != TargetKind.URL:
        return target.address
    hostname = urlparse(target.address).hostname
    if not hostname:
        raise PluginError(f"could not extract a host from url target address '{target.address}'")
    return hostname


class NetworkPlugin(Plugin):
    name = "network"
    version = "0.1.0"
    description = "TCP/service discovery via nmap."
    required_tool = "nmap"
    expected_kind = None  # nmap works against either a host/IP or a URL's host

    options_schema = (
        PluginOption(name="ports", description="nmap -p, e.g. 22,80,443 or 1-1024."),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["nmap", "--version"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")

        xml_path = execution.path("nmap.xml")
        args = ["nmap", "-sV", "-Pn", "-oX", str(xml_path)]
        ports = options.get("ports")
        if ports:
            args += ["-p", str(ports)]
        args.append(_scan_host(target))
        return args

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        hosts: list[dict[str, Any]] = []
        xml_path = execution.path("nmap.xml")
        if xml_path.exists():
            hosts = self._parse_xml(xml_path)

        return {
            "target": target.address,
            "tool": "nmap",
            "hosts": hosts,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
        }

    @staticmethod
    def _parse_xml(xml_path: Path) -> list[dict[str, Any]]:
        hosts: list[dict[str, Any]] = []
        try:
            root = ElementTree.parse(xml_path).getroot()
        except ElementTree.ParseError:
            return hosts

        for host_el in root.findall("host"):
            address_el = host_el.find("address")
            ports: list[dict[str, Any]] = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    service_el = port_el.find("service")
                    ports.append(
                        {
                            "port": port_el.get("portid"),
                            "protocol": port_el.get("protocol"),
                            "state": state_el.get("state") if state_el is not None else None,
                            "service": service_el.get("name") if service_el is not None else None,
                            "product": service_el.get("product") if service_el is not None else None,
                            "version": service_el.get("version") if service_el is not None else None,
                        }
                    )
            hosts.append(
                {
                    "address": address_el.get("addr") if address_el is not None else None,
                    "ports": ports,
                }
            )
        return hosts
