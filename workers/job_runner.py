from __future__ import annotations

import os
import socket
import traceback

from core.models import WriteBatch
from database.connection import connect_database
from database.migrations import migrate
from database.repositories import finish_job, get_job, mark_job_running
from db_writer import DBWriter
from workers.csv_worker import CsvAnalysisWorker
from workers.pcap_worker import PcapAnalysisWorker


def run_csv_job(database_path: str, source_path: str, job_id: str, batch_size: int = 1000) -> dict[str, int]:
    connection = connect_database(database_path)
    migrate(connection)
    job = get_job(connection, job_id)
    if job is None:
        connection.close()
        raise ValueError(f"unknown job: {job_id}")
    if job["status"] not in {"queued", "running"}:
        connection.close()
        raise ValueError(f"job is not runnable: {job['status']}")
    mark_job_running(connection, job_id, f"{socket.gethostname()}:{os.getpid()}")
    connection.close()

    writer = DBWriter(database_path)
    writer.open()
    worker = CsvAnalysisWorker(batch_size=batch_size)
    try:
        result = worker.run(source_path, job_id, writer.apply_batch)
        connection = connect_database(database_path)
        migrate(connection)
        finish_job(connection, job_id, "completed")
        connection.close()
        writer.close()
        return result
    except Exception as exc:
        connection = connect_database(database_path)
        migrate(connection)
        finish_job(connection, job_id, "failed", f"{exc}\n{traceback.format_exc(limit=3)}")
        connection.close()
        writer.close()
        raise


def run_pcap_job(database_path: str, source_path: str, job_id: str, batch_size: int = 1000) -> dict[str, int]:
    connection = connect_database(database_path)
    migrate(connection)
    job = get_job(connection, job_id)
    if job is None:
        connection.close()
        raise ValueError(f"unknown job: {job_id}")
    if job["status"] not in {"queued", "running"}:
        connection.close()
        raise ValueError(f"job is not runnable: {job['status']}")
    mark_job_running(connection, job_id, f"{socket.gethostname()}:{os.getpid()}")
    connection.close()
    writer = DBWriter(database_path)
    writer.open()
    try:
        result = PcapAnalysisWorker(batch_size=batch_size).run(source_path, job_id, writer.apply_batch)
        connection = connect_database(database_path)
        migrate(connection)
        finish_job(connection, job_id, "completed")
        connection.close()
        writer.close()
        return result
    except Exception as exc:
        connection = connect_database(database_path)
        migrate(connection)
        finish_job(connection, job_id, "failed", f"{exc}\n{traceback.format_exc(limit=3)}")
        connection.close()
        writer.close()
        raise

