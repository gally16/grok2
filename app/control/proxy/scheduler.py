"""Proxy clearance refresh scheduler.

Periodically refreshes ClearanceBundles for managed (FlareSolverr) mode.
Previously inline in ProxyDirectory; extracted for separation of concerns.
"""

import asyncio

from app.platform.logging.logger import logger
from app.platform.config.snapshot import get_config
from app.control.proxy import ProxyDirectory


class ProxyClearanceScheduler:
    """Periodically refreshes proxy clearance bundles."""

    def __init__(self, directory: ProxyDirectory) -> None:
        self._directory = directory
        self._task: asyncio.Task | None = None
        self._running = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("proxy clearance scheduler started")

    def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info("proxy clearance scheduler stopped")

    async def _loop(self) -> None:
        # Warm up immediately on start so the first request doesn't block.
        await self._warm_up()
        while self._running:
            try:
                interval = self._get_interval()
                await asyncio.sleep(interval)
                if not self._running:
                    break
                await self._refresh()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(
                    "proxy clearance scheduler loop failed: error_type={} error={}",
                    type(exc).__name__,
                    exc,
                )
                await asyncio.sleep(60)

    async def _warm_up(self) -> None:
        """Pre-fetch clearance bundles without invalidating existing ones."""
        try:
            await self._directory.load()
            await self._directory.warm_up()
            logger.debug("proxy clearance warm-up completed")
        except Exception as exc:
            logger.warning("proxy clearance warm-up failed: error={}", exc)

    async def _refresh(self) -> None:
        """Build fresh clearance bundles and swap atomically (build-then-swap).

        Old bundles are kept if FlareSolverr is unavailable, so a transient
        refresh failure never leaves requests without clearance.
        """
        try:
            await self._directory.load()
            await self._directory.refresh_clearance_safe()
            logger.debug("proxy clearance refresh completed")
        except Exception as exc:
            logger.warning("proxy clearance refresh failed: error={}", exc)

    def _get_interval(self) -> int:
        """Return refresh interval in seconds from config."""
        cfg = get_config()
        return cfg.get_int("proxy.clearance.refresh_interval", 600)


class SubscriptionScheduler:
    """Leader-only scheduler for subscription-driven proxy pools.

    Two cadences:
      - full refresh  → re-pull subscription, regenerate mihomo config, reload,
        retest  (proxy.subscription.refresh_interval_sec, default 1800)
      - light retest  → re-measure latency of the existing pool only
        (proxy.subscription.test_interval_sec, default 300)
    """

    def __init__(self) -> None:
        self._tasks: list[asyncio.Task] = []
        self._stop = asyncio.Event()

    def is_running(self) -> bool:
        return any(not t.done() for t in self._tasks)

    @staticmethod
    def _source_sig() -> tuple:
        """Fingerprint of the config fields that determine the node *set* (urls,
        ports, host). A change here means the pool must be re-pulled + mihomo
        reloaded (full refresh), not merely re-measured (retest)."""
        cfg = get_config()
        urls = tuple(
            u for u in cfg.get_list("proxy.subscription.urls", []) if str(u).strip()
        )
        return (
            urls,
            cfg.get_str("proxy.subscription.mihomo_api", "http://mihomo:9090"),
            cfg.get_str("proxy.subscription.mihomo_secret", ""),
            cfg.get_str("proxy.subscription.mihomo_host", "mihomo"),
            cfg.get_int("proxy.subscription.listener_base_port", 7100),
            cfg.get_int("proxy.subscription.mihomo_controller_port", 9090),
            cfg.get_str("proxy.subscription.mihomo_config_path", "/data/mihomo.yaml"),
        )

    def start(self) -> None:
        if self.is_running():
            return
        self._stop.clear()
        self._tasks = [
            asyncio.create_task(self._refresh_loop(), name="subscription-refresh"),
            asyncio.create_task(self._retest_loop(), name="subscription-retest"),
        ]
        logger.info("subscription scheduler started")

    def stop(self) -> None:
        was_running = self.is_running()
        self._stop.set()
        for t in self._tasks:
            if not t.done():
                t.cancel()
        self._tasks = []
        if was_running:
            logger.info("subscription scheduler stopped")

    async def _refresh_loop(self) -> None:
        from .subscription import get_subscription_manager

        manager = get_subscription_manager()
        # Warm up immediately so the pool exists before the first request.
        try:
            await manager.refresh()
        except Exception as exc:
            logger.warning("subscription warm-up refresh failed: error={}", exc)
        while not self._stop.is_set():
            interval = get_config().get_int(
                "proxy.subscription.refresh_interval_sec", 1800
            )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=float(interval))
                break
            except asyncio.TimeoutError:
                pass
            try:
                await manager.refresh()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("subscription refresh failed: error={}", exc)

    async def _retest_loop(self) -> None:
        from .subscription import get_subscription_manager

        manager = get_subscription_manager()
        # Poll config at a short cadence so flipping verify_with_grok re-probes
        # the pool within ~poll seconds instead of waiting the full interval.
        # A toggle takes effect on the next poll (≤ poll seconds), not literally
        # instantly; a flip-and-flip-back within one poll window is a no-op.
        last_verify = get_config().get_bool(
            "proxy.subscription.verify_with_grok", False
        )
        last_source = self._source_sig()
        waited = 0
        while not self._stop.is_set():
            interval = get_config().get_int("proxy.subscription.test_interval_sec", 300)
            # Clamp poll so a tiny test_interval_sec is still honored roughly.
            poll = min(5, max(1, interval))
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=float(poll))
                break
            except asyncio.TimeoutError:
                pass
            waited += poll
            cur_verify = get_config().get_bool(
                "proxy.subscription.verify_with_grok", False
            )
            cur_source = self._source_sig()
            # Source set changed (subscription added/edited, port/host moved) →
            # re-pull + regenerate mihomo config now instead of waiting the full
            # refresh interval; retest alone would never pick up new nodes.
            if cur_source != last_source:
                logger.info("subscription source config changed -> full refresh now")
                last_source, last_verify, waited = cur_source, cur_verify, 0
                try:
                    await manager.refresh()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning(
                        "subscription source-change refresh failed: error={}", exc
                    )
                continue
            toggled = cur_verify != last_verify
            if toggled:
                logger.info(
                    "subscription verify mode changed -> re-probing now: "
                    "verify_with_grok={}",
                    cur_verify,
                )
            if not (toggled or waited >= interval):
                continue
            last_verify = cur_verify
            waited = 0
            try:
                await manager.retest()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("subscription retest failed: error={}", exc)


__all__ = ["ProxyClearanceScheduler", "SubscriptionScheduler"]
