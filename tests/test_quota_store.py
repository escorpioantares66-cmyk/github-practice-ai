from concurrent.futures import ProcessPoolExecutor
import os

from stage2_sdk_ai import quota_store


def _reserve_in_child(args):
    db_path, identity, reservation_id = args
    os.environ["AGENT_QUOTA_DB_PATH"] = db_path
    return quota_store.reserve_budget(
        identity, "2026-10-31", reservation_id, 0.6, 1.0
    )


def _rate_in_child(args):
    db_path, identity = args
    os.environ["AGENT_QUOTA_DB_PATH"] = db_path
    return quota_store.check_rate_limit(identity, "api", 5)


def test_rate_limit_persists_across_connections(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_QUOTA_DB_PATH", str(tmp_path / "quota.sqlite3"))
    for _ in range(3):
        assert quota_store.check_rate_limit("requester-a", "api", 3, now=100)
    assert quota_store.check_rate_limit("requester-a", "api", 3, now=100) is False
    assert quota_store.check_rate_limit("requester-a", "api", 3, now=101) is False
    assert quota_store.check_rate_limit("requester-b", "api", 3, now=101) is True


def test_rate_limit_window_expires_using_persisted_wall_clock(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_QUOTA_DB_PATH", str(tmp_path / "quota.sqlite3"))
    assert quota_store.check_rate_limit("requester-a", "api", 1, now=100)
    assert quota_store.check_rate_limit("requester-a", "api", 1, now=161)


def test_rate_limit_is_atomic_across_processes(monkeypatch, tmp_path):
    db = str(tmp_path / "quota.sqlite3")
    monkeypatch.setenv("AGENT_QUOTA_DB_PATH", db)
    quota_store.check_rate_limit("warmup", "api", 1)
    args = [(db, "same-requester") for _ in range(20)]
    with ProcessPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(_rate_in_child, args))
    assert sum(results) == 5


def test_cost_reservations_are_atomic_across_processes(monkeypatch, tmp_path):
    db = str(tmp_path / "quota.sqlite3")
    monkeypatch.setenv("AGENT_QUOTA_DB_PATH", db)
    quota_store.get_daily_usage("warmup", "2026-10-31")
    args = [(db, "same-requester", f"reservation-{i}") for i in range(8)]
    with ProcessPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(_reserve_in_child, args))
    assert sum(results) == 1


def test_daily_usage_and_reservations_survive_reopen(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_QUOTA_DB_PATH", str(tmp_path / "quota.sqlite3"))
    assert quota_store.reserve_budget("requester-a", "2026-10-31", "r1", 0.4, 1.0)
    usage = quota_store.get_daily_usage("requester-a", "2026-10-31")
    assert usage["reserved"] == 0.4
    assert quota_store.reserve_budget("requester-a", "2026-10-31", "r2", 0.5, 1.0)
    assert quota_store.reserve_budget("requester-a", "2026-10-31", "r3", 0.2, 1.0) is False


def test_model_usage_records_token_counts_and_cost(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_QUOTA_DB_PATH", str(tmp_path / "quota.sqlite3"))
    result = quota_store.record_model_usage(
        "requester-a", "2026-10-31", 1000, 500, 0.00045
    )
    assert result["total"] == 0.00045
    assert result["input_tokens"] == 1000
    assert result["output_tokens"] == 500
    assert result["calls"] == 1


def test_database_and_directory_permissions_are_private(monkeypatch, tmp_path):
    import stat

    db = tmp_path / "private" / "quotas.sqlite3"
    monkeypatch.setenv("AGENT_QUOTA_DB_PATH", str(db))
    quota_store.check_rate_limit("requester-a", "api", 10)
    assert stat.S_IMODE(db.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
