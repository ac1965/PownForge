from __future__ import annotations

import json
import shutil
from typing import Any
from urllib.parse import urlparse

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.api import parse_http_response, require_same_origin
from pownforge.plugins.base import Plugin, PluginError, PluginExecution

# Public, unauthenticated discovery documents only (OpenID Connect Discovery
# 1.0 and RFC 8414). This plugin never sends credentials and never contacts
# the endpoints the document advertises -- it records the document itself.
_DOCUMENTS = {
    "openid-configuration": "/.well-known/openid-configuration",
    "oauth-authorization-server": "/.well-known/oauth-authorization-server",
}
_DEFAULT_TIMEOUT_SECONDS = 30

_RECORDED_FIELDS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "end_session_endpoint",
    "scopes_supported",
    "response_types_supported",
    "grant_types_supported",
    "code_challenge_methods_supported",
    "token_endpoint_auth_methods_supported",
    "id_token_signing_alg_values_supported",
)


class IdentityPlugin(Plugin):
    name = "identity"
    version = "0.1.0"
    description = "Fetch an identity provider's public OIDC/OAuth discovery document once via curl."
    required_tool = "curl"
    expected_kind = TargetKind.URL
    kind_hint = "Use the identity provider's base URL (issuer), e.g. http://lab-idp:8080/realms/lab."

    options_schema = (
        PluginOption(
            name="document",
            description="Which public discovery document to fetch.",
            default="openid-configuration",
            choices=sorted(_DOCUMENTS),
        ),
        PluginOption(name="timeout", description="curl --max-time, seconds.", default=str(_DEFAULT_TIMEOUT_SECONDS)),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["curl", "--version"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)

        document = str(options.get("document", "openid-configuration"))
        if document not in _DOCUMENTS:
            raise PluginError(
                f"identity plugin --option document must be one of {', '.join(sorted(_DOCUMENTS))}"
            )
        try:
            timeout = int(options.get("timeout", _DEFAULT_TIMEOUT_SECONDS))
        except ValueError as exc:
            raise PluginError("identity plugin --option timeout must be an integer (seconds)") from exc

        url = target.address.rstrip("/") + _DOCUMENTS[document]
        require_same_origin(self.name, target.address, url)
        execution.data["url"] = url
        return [
            "curl", "-sS", "-i",
            "--max-time", str(timeout),
            "--proto", "=http,https",
            "-H", "Accept: application/json",
            url,
        ]

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        url = execution.data.get("url", target.address)
        status, _reason, headers, body = parse_http_response(raw_stdout)

        metadata: dict[str, Any] | None = None
        if status == 200:
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                metadata = parsed

        summary = {k: metadata[k] for k in _RECORDED_FIELDS if metadata and k in metadata}
        return {
            "target": target.address,
            "tool": "curl",
            "url": url,
            "status": status,
            "content_type": headers.get("content-type"),
            "metadata_found": metadata is not None,
            "metadata": summary,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": self._findings(target.address, url, metadata) if metadata else [],
        }

    @staticmethod
    def _findings(base: str, url: str, metadata: dict[str, Any]) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []

        issuer = metadata.get("issuer")
        if isinstance(issuer, str) and issuer.rstrip("/") != base.rstrip("/"):
            findings.append(
                {
                    "title": "Discovery document issuer differs from the registered address",
                    "severity": "info",
                    "detail": f"issuer={issuer} registered={base}",
                }
            )

        algs = metadata.get("id_token_signing_alg_values_supported") or []
        if isinstance(algs, list) and any(str(a).lower() == "none" for a in algs):
            findings.append(
                {
                    "title": "Unsigned ID tokens advertised (alg 'none' in id_token_signing_alg_values_supported)",
                    "severity": "medium",
                    "detail": url,
                }
            )

        grants = metadata.get("grant_types_supported") or []
        responses = metadata.get("response_types_supported") or []
        if (isinstance(grants, list) and "implicit" in grants) or (
            isinstance(responses, list) and any("token" in str(r).split() for r in responses)
        ):
            findings.append(
                {
                    "title": "Implicit flow advertised (discouraged by OAuth 2.0 Security BCP)",
                    "severity": "info",
                    "detail": f"grant_types={grants} response_types={responses}",
                }
            )
        if isinstance(grants, list) and "password" in grants:
            findings.append(
                {
                    "title": "Resource owner password credentials grant advertised",
                    "severity": "low",
                    "detail": url,
                }
            )

        pkce = metadata.get("code_challenge_methods_supported")
        if isinstance(pkce, list) and "S256" not in pkce:
            findings.append(
                {
                    "title": "PKCE S256 not listed in code_challenge_methods_supported",
                    "severity": "low",
                    "detail": f"code_challenge_methods_supported={pkce}",
                }
            )

        insecure = sorted(
            key
            for key, value in metadata.items()
            if key.endswith(("_endpoint", "_uri"))
            and isinstance(value, str)
            and urlparse(value).scheme == "http"
            and urlparse(value).hostname not in ("localhost", "127.0.0.1")
        )
        if insecure:
            findings.append(
                {
                    "title": "Discovery document advertises plain-http endpoints",
                    "severity": "low",
                    "detail": ", ".join(insecure),
                }
            )
        return findings
