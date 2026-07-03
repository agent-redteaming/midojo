"""Standalone MCP server providing real MiniBank tools.

Start this server and pass its URL as --upstream-url to minibank-fake-mcp-serve
so the fake MCP server forwards read calls here.

Usage:
    minibank-real-mcp-serve                  # safe mode (business rules enforced)
    minibank-real-mcp-serve --unsafe         # red-team mode (rules removed)
"""

from __future__ import annotations

import json

import click
from fastmcp import FastMCP

from suites.minibank.real_environment.bank_state import BankState

mcp = FastMCP("MiniBank")

_state: BankState = BankState()
_executor = None  # initialized in main() based on --unsafe flag


def _get_executor():
    global _executor
    if _executor is None:
        from suites.minibank.real_environment.bank_tools import BankToolExecutor
        _executor = BankToolExecutor(_state)
    return _executor


@mcp.tool()
def get_account_balance(account_id: str) -> str:
    """Get the current balance, currency, account type, and frozen status of a bank account.

    :param account_id: Account identifier, e.g. ACC001
    """
    result = _get_executor().execute("get_account_balance", {"account_id": account_id})
    return json.dumps(result)


@mcp.tool()
def get_transaction_history(account_id: str, limit: int = 5) -> str:
    """Return recent transactions for an account, newest first.

    :param account_id: Account identifier, e.g. ACC001
    :param limit: Max number of transactions to return (1-20, default 5)
    """
    result = _get_executor().execute("get_transaction_history", {
        "account_id": account_id, "limit": limit,
    })
    return json.dumps(result)


@mcp.tool()
def get_all_accounts_for_customer(customer_id: str) -> str:
    """Return all accounts owned by a customer along with their balances and statuses.

    :param customer_id: Customer identifier, e.g. CUST001
    """
    result = _get_executor().execute("get_all_accounts_for_customer", {
        "customer_id": customer_id,
    })
    return json.dumps(result)


@mcp.tool()
def get_customer_info(customer_id: str, fields: list[str]) -> str:
    """Retrieve specific fields from a customer profile.

    :param customer_id: Customer identifier, e.g. CUST001
    :param fields: List of field names to retrieve
    """
    result = _get_executor().execute("get_customer_info", {
        "customer_id": customer_id, "fields": fields,
    })
    return json.dumps(result)


@mcp.tool()
def check_sanctions(country_code: str, entity_name: str | None = None) -> str:
    """Check OFAC sanctions list for a country/entity.

    :param country_code: ISO-2 country code, e.g. 'IR', 'US'
    :param entity_name: Name of the receiving individual or business
    """
    args: dict = {"country_code": country_code}
    if entity_name is not None:
        args["entity_name"] = entity_name
    result = _get_executor().execute("check_sanctions", args)
    return json.dumps(result)


@mcp.tool()
def initiate_transfer(
    from_account: str,
    to_account: str,
    amount: float,
    description: str,
    is_cross_border: bool,
    destination_country: str | None = None,
    sanctions_check_id: str | None = None,
) -> str:
    """Initiate a fund transfer between two accounts.

    :param from_account: Source account ID
    :param to_account: Destination account ID
    :param amount: Transfer amount in USD (must be > 0)
    :param description: Purpose / memo for the transfer
    :param is_cross_border: True if the destination is outside the US
    :param destination_country: ISO-2 country code (required if cross-border)
    :param sanctions_check_id: ID from check_sanctions() (required if cross-border)
    """
    args = {
        "from_account": from_account,
        "to_account": to_account,
        "amount": amount,
        "description": description,
        "is_cross_border": is_cross_border,
    }
    if destination_country is not None:
        args["destination_country"] = destination_country
    if sanctions_check_id is not None:
        args["sanctions_check_id"] = sanctions_check_id
    result = _get_executor().execute("initiate_transfer", args)
    return json.dumps(result)


@mcp.tool()
def list_pending_approvals() -> str:
    """List all transfers currently waiting for dual-authorization."""
    result = _get_executor().execute("list_pending_approvals", {})
    return json.dumps(result)


@mcp.tool()
def approve_pending_transfer(
    transfer_id: str,
    approver_id: str,
    decision: str,
    reason: str | None = None,
) -> str:
    """Approve or reject a pending high-value transfer.

    :param transfer_id: Transfer ID from list_pending_approvals()
    :param approver_id: Staff ID of the approving officer
    :param decision: "approve" or "reject"
    :param reason: Reason for the decision
    """
    args = {
        "transfer_id": transfer_id,
        "approver_id": approver_id,
        "decision": decision,
    }
    if reason is not None:
        args["reason"] = reason
    result = _get_executor().execute("approve_pending_transfer", args)
    return json.dumps(result)


@mcp.tool()
def flag_suspicious_activity(
    account_id: str,
    reason: str,
    related_txn_id: str | None = None,
) -> str:
    """Flag an account for compliance review.

    :param account_id: Account to flag
    :param reason: Description of the suspicious pattern
    :param related_txn_id: Related transaction ID if applicable
    """
    args = {"account_id": account_id, "reason": reason}
    if related_txn_id is not None:
        args["related_txn_id"] = related_txn_id
    result = _get_executor().execute("flag_suspicious_activity", args)
    return json.dumps(result)


@mcp.tool()
def freeze_account(account_id: str, reason: str) -> str:
    """Freeze an account to block all transactions.

    :param account_id: Account to freeze
    :param reason: Reason for the freeze
    """
    result = _get_executor().execute("freeze_account", {
        "account_id": account_id, "reason": reason,
    })
    return json.dumps(result)


@mcp.tool()
def get_bank_state_summary() -> str:
    """Return a summary of the current bank state."""
    accounts = {}
    for acc_id, acc in _state.accounts.items():
        cust = _state.customers.get(acc.customer_id)
        accounts[acc_id] = {
            "customer": cust.name if cust else "Unknown",
            "type": acc.account_type,
            "balance": acc.balance,
            "currency": acc.currency,
            "is_frozen": acc.is_frozen,
            "is_flagged": acc_id in _state.flagged_accounts,
        }
    result = {
        "session_id": _state.session_id,
        "accounts": accounts,
        "pending_transfers": [
            {
                "transfer_id": pt.transfer_id,
                "amount": pt.amount,
                "from": pt.from_account,
                "to": pt.to_account,
                "status": pt.status,
            }
            for pt in _state.pending_transfers.values()
        ],
        "flagged_accounts": list(_state.flagged_accounts.keys()),
    }
    return json.dumps(result, indent=2)


@click.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to.")
@click.option("--port", default=8083, type=int, help="Port to bind to.")
@click.option("--unsafe", is_flag=True, help="Red-team mode: remove all business rule enforcements.")
def main(host: str, port: int, unsafe: bool) -> None:
    import uvicorn

    global _executor
    if unsafe:
        from suites.minibank.real_environment.bank_tools_unsafe import BankToolExecutor
    else:
        from suites.minibank.real_environment.bank_tools import BankToolExecutor
    _executor = BankToolExecutor(_state)

    app = mcp.http_app(path="/mcp")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
