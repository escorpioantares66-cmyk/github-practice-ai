"""Versioned HTTP interface for external sandbox approvals."""
from __future__ import annotations

import os
import re

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from . import auth, sandbox_approval

router = APIRouter(prefix="/v1/sandbox/approvals", tags=["sandbox-approvals"])
_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SandboxScope(StrictModel):
    repository: str = Field(min_length=3, max_length=201)
    sandbox_id: str = Field(min_length=1, max_length=128)
    base_sha: str = Field(min_length=40, max_length=64)
    head_sha: str = Field(min_length=40, max_length=64)
    diff_sha256: str = Field(min_length=64, max_length=64)
    action: str = "prepare_pull_request"


class CreateSandboxApproval(StrictModel):
    scope: SandboxScope


class ConsumeSandboxApproval(StrictModel):
    request_id: str = Field(min_length=36, max_length=36)
    nonce: str = Field(min_length=64, max_length=64)
    scope: SandboxScope


def _requester_identity(x_api_key: str | None) -> str:
    if not auth.verify_api_key(x_api_key or ""):
        raise HTTPException(status_code=401, detail="Invalid API key")
    identity = auth.approval_requester_identity(x_api_key)
    if identity is None:
        raise HTTPException(status_code=401, detail="Requester identity unavailable")
    if not auth.check_rate_limit(identity, role="sandbox-requester"):
        raise HTTPException(status_code=429, detail="Requester rate limit exceeded")
    return identity


def _approver_identity(x_approver_key: str | None) -> str:
    if not auth.verify_approver_key(x_approver_key):
        raise HTTPException(status_code=403, detail="Invalid or missing approver credentials")
    try:
        identity = auth.approver_identity(x_approver_key or "")
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Approver identity unavailable") from exc
    if not auth.check_rate_limit(identity, role="sandbox-approver"):
        raise HTTPException(status_code=429, detail="Approver rate limit exceeded")
    return identity


def _raise_http(exc: sandbox_approval.SandboxApprovalError) -> None:
    if isinstance(exc, sandbox_approval.SandboxApprovalNotFound):
        raise HTTPException(status_code=404, detail="Sandbox approval not found") from exc
    if isinstance(exc, sandbox_approval.SandboxApprovalForbidden):
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if isinstance(exc, sandbox_approval.SandboxApprovalConflict):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, sandbox_approval.SandboxApprovalConfigurationError):
        raise HTTPException(
            status_code=503, detail="Sandbox approval authority unavailable"
        ) from exc
    raise HTTPException(
        status_code=503, detail="Sandbox approval requires operator review"
    ) from exc


@router.post("")
def create_sandbox_approval(
    req: CreateSandboxApproval,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
):
    requester = _requester_identity(x_api_key)
    try:
        return sandbox_approval.create_request(
            req.scope.model_dump(),
            requester=requester,
            issuer=os.getenv("SANDBOX_APPROVAL_ISSUER", ""),
            audience=os.getenv("SANDBOX_APPROVAL_AUDIENCE", ""),
        )
    except sandbox_approval.SandboxApprovalError as exc:
        _raise_http(exc)


@router.post("/{approval_id}/approve")
def approve_sandbox_request(
    approval_id: str,
    x_approver_key: str | None = Header(None, alias="X-Approver-Key"),
):
    if not _ID_RE.fullmatch(approval_id):
        raise HTTPException(status_code=422, detail="Invalid approval ID")
    _approver_identity(x_approver_key)
    try:
        return sandbox_approval.decide(
            approval_id, approver_key=x_approver_key or "", decision="approved"
        )
    except sandbox_approval.SandboxApprovalError as exc:
        _raise_http(exc)


@router.post("/{approval_id}/deny")
def deny_sandbox_request(
    approval_id: str,
    x_approver_key: str | None = Header(None, alias="X-Approver-Key"),
):
    if not _ID_RE.fullmatch(approval_id):
        raise HTTPException(status_code=422, detail="Invalid approval ID")
    _approver_identity(x_approver_key)
    try:
        return sandbox_approval.decide(
            approval_id, approver_key=x_approver_key or "", decision="denied"
        )
    except sandbox_approval.SandboxApprovalError as exc:
        _raise_http(exc)


@router.get("/{approval_id}/decision")
def get_sandbox_decision(
    approval_id: str,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
):
    if not _ID_RE.fullmatch(approval_id):
        raise HTTPException(status_code=422, detail="Invalid approval ID")
    requester = _requester_identity(x_api_key)
    try:
        return sandbox_approval.get_decision(approval_id, requester=requester)
    except sandbox_approval.SandboxApprovalError as exc:
        _raise_http(exc)


@router.get("/{approval_id}")
def inspect_sandbox_approval(
    approval_id: str,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
):
    if not _ID_RE.fullmatch(approval_id):
        raise HTTPException(status_code=422, detail="Invalid approval ID")
    requester = _requester_identity(x_api_key)
    try:
        return sandbox_approval.inspect(approval_id, requester=requester)
    except sandbox_approval.SandboxApprovalError as exc:
        _raise_http(exc)


@router.post("/{approval_id}/consume")
def consume_sandbox_approval(
    approval_id: str,
    req: ConsumeSandboxApproval,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
):
    if not _ID_RE.fullmatch(approval_id):
        raise HTTPException(status_code=422, detail="Invalid approval ID")
    requester = _requester_identity(x_api_key)
    try:
        return sandbox_approval.consume(
            approval_id,
            requester=requester,
            request_id=req.request_id,
            nonce=req.nonce,
            scope=req.scope.model_dump(),
        )
    except sandbox_approval.SandboxApprovalError as exc:
        _raise_http(exc)
