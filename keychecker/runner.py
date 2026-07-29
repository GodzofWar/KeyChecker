"""Run checks concurrently."""

from __future__ import annotations

import asyncio
from typing import List

import httpx

from .checkers import REGISTRY
from .models import CheckResult, Job


async def _run_job(job: Job, client: httpx.AsyncClient, sem: asyncio.Semaphore) -> CheckResult:
    checker = REGISTRY[job.service](job.credentials, job.label)
    async with sem:
        try:
            return await checker.check(client)
        except Exception as exc:  # defensive: never let one checker kill the run
            return checker.error(f"unhandled exception: {exc}")


async def run_checks(
    jobs: List[Job], concurrency: int = 10, timeout: float = 15.0
) -> List[CheckResult]:
    sem = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_connections=concurrency)
    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        follow_redirects=True,
        headers={"User-Agent": "KeyChecker/0.1"},
    ) as client:
        return await asyncio.gather(*(_run_job(j, client, sem) for j in jobs))
