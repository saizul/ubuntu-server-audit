"""Importing this package registers every check."""

from ubuntu_server_audit.checks import (  # noqa: F401
    accounts,
    database,
    firewall,
    housekeeping,
    kernel,
    ssh,
    updates,
    web,
)
