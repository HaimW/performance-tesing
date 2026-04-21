import os
import logging
import yaml
import gevent
from locust import HttpUser, between, events
from locust.runners import MasterRunner

_cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
with open(_cfg_path) as _f:
    _cfg = yaml.safe_load(_f)

_target = _cfg["target"]
_scenarios = _cfg["scenarios"]
_kpi = _cfg["kpi"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
_log = logging.getLogger("locust.kpi")


def _make_task(endpoint):
    method = endpoint["method"].lower()
    path = endpoint["path"]
    name = endpoint["name"]
    expected = endpoint.get("expected_status", 200)
    if isinstance(expected, int):
        expected = [expected]
    body = endpoint.get("body")

    def _task(self):
        kwargs = {"name": name, "catch_response": True}
        if method == "post" and body:
            kwargs["json"] = body
        with getattr(self.client, method)(path, **kwargs) as resp:
            if resp.status_code not in expected:
                resp.failure(f"{name} got {resp.status_code}")

    _task.__name__ = name.replace(" ", "_").replace("/", "_")
    return _task


# Build weighted task list: each endpoint repeated `weight` times
_task_list = []
for _ep in _scenarios["endpoints"]:
    _task_list.extend([_make_task(_ep)] * _ep["weight"])


class WebsiteUser(HttpUser):
    # Use origin_url when set so requests bypass the CDN entirely
    host = _target.get("origin_url") or _target["url"]
    wait_time = between(_scenarios["think_time_min"], _scenarios["think_time_max"])
    tasks = _task_list

    def on_start(self):
        if _target.get("host_header"):
            self.client.headers.update({"Host": _target["host_header"]})
        if not _target.get("tls_verify", True):
            self.client.verify = False


def _periodic_reporter(environment):
    interval = _kpi["report_interval"]
    while True:
        gevent.sleep(interval)
        stats = environment.runner.stats.total
        _log.info(
            "[KPI] users=%d | RPS=%.1f | RT_median=%.0fms | RT_p95=%.0fms | error_rate=%.2f%%",
            environment.runner.user_count,
            stats.current_rps,
            stats.get_response_time_percentile(0.50) or 0,
            stats.get_response_time_percentile(0.95) or 0,
            stats.fail_ratio * 100,
        )


@events.init.add_listener
def on_locust_init(environment, **kwargs):
    if isinstance(environment.runner, MasterRunner):
        gevent.spawn(_periodic_reporter, environment)
