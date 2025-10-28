from a import create_topology
from mininet.log import setLogLevel, info
import re
import statistics
import time
import os
import logging 

def parse_time(output):
    match = re.search(r"Query time: (\d+) msec", output)
    return int(match.group(1)) if match else None

def test_dns(net, host_name, url_file, dns_server="8.8.8.8"):
    h = net.get(host_name)
    latencies, success, fail, total_data = [], 0, 0, 0

    if not os.path.exists(url_file):
        info(f"URL file not found: {url_file}\n")
        return None

    with open(url_file) as f:
        urls = [u.strip() for u in f if u.strip()]

    info(f"\n--- Testing host {host_name} with {len(urls)} URLs ---\n")

    info(f"[{host_name}] Setting DNS to {dns_server}\n")
    h.cmd(f"echo 'nameserver {dns_server}' > /etc/resolv.conf")

    for idx, url in enumerate(urls, start=1):
        info(f"[{host_name}] Querying ({idx}/{len(urls)}): {url} ... ")
        cmd = f"dig +stats @{dns_server} {url}"
        output = h.cmd(cmd)
        lookup_time = parse_time(output)
        if lookup_time is not None:
            success += 1
            latencies.append(lookup_time)
            total_data += len(url)
            info(f"Success ({lookup_time} ms)\n")
        else:
            fail += 1
            info(f"Failed\n")

    avg_latency = statistics.mean(latencies) if latencies else float('nan')
    total_time = sum(latencies) / 1000 if latencies else 1
    throughput = (total_data / total_time) if total_time > 0 else 0

    info(f"URLs tested: {len(urls)}\n")
    info(f"Successful: {success}, Failed: {fail}\n")
    info(f"Average latency: {avg_latency:.2f} ms\n")
    info(f"Throughput: {throughput:.2f} bytes/sec\n\n")

    return {"host": host_name, "avg_latency": avg_latency,
            "throughput": throughput, "success": success, "fail": fail}

def main():
    setLogLevel('info')
    logger = logging.getLogger()
    
    file_handler = logging.FileHandler('dns_test.log', mode='w')
    
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)

    info("Logging to console and dns_test.log")
    net = create_topology()

    results = []
    for i in range(1, 5):
        results.append(test_dns(net, f"h{i}", f"urls_h{i}.txt"))

    for r in results:
        if r:
            info(f"{r['host']}: {r['avg_latency']:.2f} ms | {r['throughput']:.2f} B/s | "
                 f"Success={r['success']} | Fail={r['fail']}\n")

    net.stop()
if __name__ == "__main__":
    main()

