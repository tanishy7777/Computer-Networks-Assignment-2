import subprocess
import re
import sys
import time
import threading
from queue import Queue

WORKER_THREADS = 30
PROCESS_TIMEOUT = 41
DIG_TRIES = "1"
DIG_WAIT = "40"

def dig_probe(domain_queue, stats_lock, latencies, successful_queries, resolution_counts):
    while True:
        domain, index = domain_queue.get()
        try:
            cmd = ['dig', f'+time={DIG_WAIT}', f'+tries={DIG_TRIES}', '+stats', '+qr', domain]
            proc_output = subprocess.run(cmd, capture_output=True, text=True, timeout=PROCESS_TIMEOUT)
            
            answer_match = re.search(r'ANSWER SECTION:\n([\w\.-]+)\.\s+\d+\s+IN\s+A\s+([\d\.]+)', proc_output.stdout, re.IGNORECASE)

            with stats_lock:
                if answer_match:
                    resolution_counts["successful"] += 1
                    time_match = re.search(r'Query time: (\d+) msec', proc_output.stdout)
                    if time_match:
                        latencies.append(int(time_match.group(1)))
                    successful_queries.append(domain)
                    print(f"[RESOLVED] {domain:<30} (Job {index})")
                else:
                    resolution_counts["failed"] += 1
                    print(f"[FAILED] {domain:<30} (Job {index})")

        except Exception:
            with stats_lock:
                resolution_counts["failed"] += 1
                print(f"[TIMEOUT] {domain:<30} (Job {index})")
        finally:
            domain_queue.task_done()

def execute_benchmark(domain_list_file):
    run_start = time.monotonic()

    with open(domain_list_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    domain_queue = Queue()
    total_queries = len(domains)

    latencies = []
    resolution_counts = {"successful": 0, "failed": 0}
    successful_queries = []
    stats_lock = threading.Lock()
    workers = []

    print(f"Starting {total_queries} queries with {WORKER_THREADS} workers:")

    for _ in range(WORKER_THREADS):
        t = threading.Thread(
            target=dig_probe,
            args=(domain_queue, stats_lock, latencies, successful_queries, resolution_counts),
            daemon=True
        )
        workers.append(t)
        t.start()

    for i, host in enumerate(domains):
        domain_queue.put((host, i))

    domain_queue.join()

    run_end = time.monotonic()
    total_duration = run_end - run_start

    ok_count = resolution_counts["successful"]
    fail_count = resolution_counts["failed"]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    throughput = total_queries / total_duration if total_duration > 0 else 0

    print(f"\nTotal Queries Attempted: {total_queries}")
    print(f"Number of successfully resolved queries: {ok_count}")
    print(f"Number of failed resolutions: {fail_count}")
    print(f"Average lookup latency: {avg_latency:.2f} ms")
    print(f"Average throughput: {throughput:.2f} queries/sec")
    print(f"Total Test Duration: {total_duration:.2f} s")

if __name__ == "__main__":
    execute_benchmark(sys.argv[1])