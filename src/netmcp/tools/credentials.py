"""Credential extraction tools (HTTP Basic, FTP, Telnet, Kerberos)."""

import base64

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from netmcp.core.formatter import OutputFormatter
from netmcp.core.security import SecurityValidator
from netmcp.interfaces.tshark import TsharkInterface


def register_credential_tools(
    mcp: FastMCP, tshark: TsharkInterface, fmt: OutputFormatter, sec: SecurityValidator
) -> None:
    """Register credential extraction MCP tools."""

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Extract Credentials",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def extract_credentials(filepath: str) -> dict:
        """
        Extract potential credentials from a PCAP file.

        Scans for:
        - HTTP Basic Authentication headers
        - FTP USER/PASS commands
        - Telnet login/password prompts
        - Kerberos AS-REQ/AS-REP hashes (crackable with hashcat)

        Args:
            filepath: Path to PCAP/PCAPNG file
        """
        try:
            validated_path = sec.sanitize_filepath(filepath)
            sec.audit_log("extract_credentials", {"filepath": str(validated_path)})
            pcap = str(validated_path)

            # Extract plaintext creds
            fields = [
                "http.authbasic",
                "ftp.request.command",
                "ftp.request.arg",
                "telnet.data",
                "frame.number",
            ]
            plaintext_rows = await tshark.export_fields(pcap, fields)

            # Extract Kerberos creds
            krb_fields = [
                "kerberos.CNameString",
                "kerberos.realm",
                "kerberos.cipher",
                "kerberos.type",
                "kerberos.msg_type",
                "frame.number",
            ]
            krb_rows = await tshark.export_fields(pcap, krb_fields)

            credentials = {"plaintext": [], "encrypted": []}

            # Process HTTP Basic Auth
            for row in plaintext_rows:
                auth = row.get("http.authbasic", "")
                if auth:
                    try:
                        decoded = base64.b64decode(auth).decode("utf-8", errors="replace")
                        if ":" in decoded:
                            username, password = decoded.split(":", 1)
                            credentials["plaintext"].append(
                                {
                                    "type": "HTTP Basic Auth",
                                    "username": username,
                                    "password": password,
                                    "frame": row.get("frame.number", ""),
                                }
                            )
                    except Exception:
                        pass

            # Process FTP
            ftp_user = None
            for row in plaintext_rows:
                cmd = row.get("ftp.request.command", "").strip().upper()
                arg = row.get("ftp.request.arg", "")
                frame = row.get("frame.number", "")

                if cmd == "USER" and arg:
                    ftp_user = arg
                    credentials["plaintext"].append(
                        {
                            "type": "FTP",
                            "username": arg,
                            "password": "",
                            "frame": frame,
                        }
                    )
                elif cmd == "PASS" and arg and ftp_user:
                    # Update last FTP entry
                    for c in reversed(credentials["plaintext"]):
                        if (
                            c["type"] == "FTP"
                            and not c["password"]
                            and c.get("username") == ftp_user
                        ):
                            c["password"] = arg
                            break
                    ftp_user = None

            # Process Telnet
            for row in plaintext_rows:
                telnet = row.get("telnet.data", "").strip()
                frame = row.get("frame.number", "")
                if not telnet:
                    continue

                telnet_lower = telnet.lower()
                if "login:" in telnet_lower or "password:" in telnet_lower:
                    credentials["plaintext"].append(
                        {
                            "type": "Telnet Prompt",
                            "data": telnet,
                            "frame": frame,
                        }
                    )
                elif telnet and " " not in telnet and ":" not in telnet:
                    # Likely username/password
                    last_prompt = None
                    for c in reversed(credentials["plaintext"]):
                        if c["type"] == "Telnet Prompt":
                            last_prompt = c
                            break
                    if last_prompt:
                        if "login:" in last_prompt.get("data", "").lower():
                            credentials["plaintext"].append(
                                {
                                    "type": "Telnet",
                                    "username": telnet,
                                    "password": "",
                                    "frame": frame,
                                }
                            )
                        elif "password:" in last_prompt.get("data", "").lower():
                            for c in reversed(credentials["plaintext"]):
                                if c["type"] == "Telnet" and not c["password"]:
                                    c["password"] = telnet
                                    break

            # Process Kerberos
            for row in krb_rows:
                cipher = row.get("kerberos.cipher", "")
                msg_type = row.get("kerberos.msg_type", "")
                if cipher and msg_type:
                    cname = row.get("kerberos.CNameString", "unknown")
                    realm = row.get("kerberos.realm", "unknown")
                    frame = row.get("frame.number", "")

                    hash_format = ""
                    cracking = ""
                    if msg_type in ("10", "30"):  # AS-REQ / TGS-REQ pre-auth
                        hash_format = f"$krb5pa$23${cname}${realm}$*${cipher}"
                        cracking = "hashcat -m 7500"
                    elif msg_type == "11":  # AS-REP
                        hash_format = f"$krb5asrep$23${cname}@{realm}:{cipher}"
                        cracking = "hashcat -m 18200"
                    elif msg_type == "12":  # TGS-REQ
                        credentials["encrypted"].append(
                            {
                                "type": "Kerberos TGS-REQ",
                                "username": cname,
                                "realm": realm,
                                "frame": frame,
                                "note": "Service ticket request — potential Kerberoasting target",
                            }
                        )

                    if hash_format:
                        credentials["encrypted"].append(
                            {
                                "type": "Kerberos",
                                "hash": hash_format,
                                "username": cname,
                                "realm": realm,
                                "frame": frame,
                                "cracking_command": cracking,
                            }
                        )

            result = {
                "filepath": str(validated_path),
                "plaintext_count": len(credentials["plaintext"]),
                "encrypted_count": len(credentials["encrypted"]),
                "plaintext": credentials["plaintext"],
                "encrypted": credentials["encrypted"],
            }
            return fmt.format_success(result, title="Credential Extraction")
        except Exception as e:
            return fmt.format_error(e, "NETMCP_004")
