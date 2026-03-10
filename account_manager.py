#!/usr/bin/env python3
"""
account_manager.py
------------------
Loads the accounts registry (accounts.yaml) and provides
per-account boto3 sessions — either via named AWS profile
or STS AssumeRole for cross-account access.

Usage (as a library):
    from account_manager import AccountManager

    mgr = AccountManager()

    for account in mgr.accounts:
        session = mgr.get_session(account)
        ec2 = session.client("ec2", region_name=account["region"])
        ...

Usage (CLI — list accounts):
    python3 account_manager.py --list
    python3 account_manager.py --verify        # test credentials for all accounts
    python3 account_manager.py --verify --account 024863982143
"""

import argparse
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

import boto3
import yaml
from botocore.exceptions import ClientError, NoCredentialsError

ACCOUNTS_FILE = Path(__file__).parent / "accounts.yaml"


def ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


class AccountManager:
    def __init__(self, accounts_file: Path = ACCOUNTS_FILE):
        if not accounts_file.exists():
            raise FileNotFoundError(
                f"accounts.yaml not found at {accounts_file}. "
                "Copy accounts.yaml.example and fill in your accounts."
            )
        with open(accounts_file) as f:
            data = yaml.safe_load(f)

        self.accounts: list[dict] = data.get("accounts", [])
        if not self.accounts:
            raise ValueError("No accounts defined in accounts.yaml")

    # ── Credential resolution ─────────────────────────────────────────────────

    def get_session(self, account: dict) -> boto3.Session:
        """
        Return an authenticated boto3 Session for the given account dict.
        Supports:
          - profile:  named AWS CLI profile
          - role_arn: STS AssumeRole (cross-account)
        """
        account_id = account["id"]
        region     = account.get("region", "us-east-1")

        # ── Option 1: named profile ────────────────────────────────────────────
        if "profile" in account:
            return boto3.Session(
                profile_name=account["profile"],
                region_name=region
            )

        # ── Option 2: STS AssumeRole ───────────────────────────────────────────
        if "role_arn" in account:
            sts = boto3.client("sts", region_name=region)
            assume_kwargs = {
                "RoleArn":         account["role_arn"],
                "RoleSessionName": f"cloud-security-agent-{account_id}",
                "DurationSeconds": account.get("session_duration", 3600),
            }
            if "external_id" in account:
                assume_kwargs["ExternalId"] = account["external_id"]

            creds = sts.assume_role(**assume_kwargs)["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region
            )

        raise ValueError(
            f"Account {account_id} ({account.get('name')}) has no 'profile' or 'role_arn' defined."
        )

    # ── Lookup helpers ────────────────────────────────────────────────────────

    def get_account(self, account_id: str) -> dict:
        """Look up an account by its AWS account ID."""
        for a in self.accounts:
            if a["id"] == account_id:
                return a
        raise KeyError(f"Account {account_id} not found in accounts.yaml")

    def get_account_by_name(self, name: str) -> dict:
        """Look up an account by its friendly name."""
        for a in self.accounts:
            if a.get("name") == name:
                return a
        raise KeyError(f"Account named '{name}' not found in accounts.yaml")

    def select(self, selector: str | None) -> list[dict]:
        """
        Return accounts matching selector:
          None / "all"     → all accounts
          "024863982143"   → account by ID
          "production"     → account by name
        """
        if selector is None or selector == "all":
            return self.accounts
        # Try ID first
        try:
            return [self.get_account(selector)]
        except KeyError:
            pass
        # Try name
        try:
            return [self.get_account_by_name(selector)]
        except KeyError:
            pass
        raise ValueError(f"No account matching '{selector}' — use account ID or name from accounts.yaml")

    # ── Credential verification ───────────────────────────────────────────────

    def verify(self, account: dict) -> tuple[bool, str]:
        """
        Call sts:GetCallerIdentity to confirm credentials work.
        Returns (success: bool, message: str).
        """
        try:
            session = self.get_session(account)
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            verified_id = identity["Account"]
            arn         = identity["Arn"]
            if verified_id != account["id"]:
                return False, (
                    f"Account ID mismatch: expected {account['id']}, "
                    f"got {verified_id} (arn: {arn})"
                )
            return True, f"✓ {account['id']} ({account.get('name', '?')}) → {arn}"
        except NoCredentialsError:
            return False, f"✗ {account['id']}: No credentials found"
        except ClientError as e:
            return False, f"✗ {account['id']}: {e}"
        except Exception as e:
            return False, f"✗ {account['id']}: Unexpected error — {e}"


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AWS Account Manager — list and verify accounts")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list",   action="store_true", help="List all configured accounts")
    group.add_argument("--verify", action="store_true", help="Verify credentials for accounts")
    parser.add_argument("--account", metavar="ID_OR_NAME",
                        help="Target a specific account (default: all)")
    args = parser.parse_args()

    mgr = AccountManager()

    if args.list:
        print(f"\n{'─'*55}")
        print(f"  Configured Accounts ({len(mgr.accounts)} total)")
        print(f"{'─'*55}")
        for a in mgr.accounts:
            auth = f"profile={a['profile']}" if "profile" in a else f"role={a['role_arn'].split(':')[-1]}"
            print(f"  {a['id']}  {a.get('name','?'):<15}  {a.get('region','?'):<15}  {auth}")
        print(f"{'─'*55}\n")
        return

    if args.verify:
        accounts = mgr.select(args.account)
        print(f"\n[{ts()}] Verifying credentials for {len(accounts)} account(s)...\n")
        all_ok = True
        for account in accounts:
            ok, msg = mgr.verify(account)
            print(f"  {msg}")
            if not ok:
                all_ok = False
        print()
        sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
