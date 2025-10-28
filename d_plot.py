import re
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import sys
from collections import defaultdict

COMPLETE_RE = re.compile(r"RESOLUTION_COMPLETE: ([\w\.-]+) \| IP: ([\d\.]+) \| Total time to resolution: ([\d\.]+)s \| SERVERS_VISITED: (\d+)")
RTT_RE = re.compile(r"Round-trip time: ([\d\.]+)s")
QUERY_RE = re.compile(r"Domain name queried: ([\w\.-]+)")

def process_resolver_logs(log_path):
    log_entries = []
    current_rtts = []
    current_domain = None

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                query_match = QUERY_RE.search(line)
                if query_match:
                    current_domain = query_match.group(1)
                    current_rtts = []
                    continue

                rtt_match = RTT_RE.search(line)
                if rtt_match:
                    current_rtts.append(float(rtt_match.group(1)))
                    continue
                
                complete_match = COMPLETE_RE.search(line)
                if complete_match and complete_match.group(1) == current_domain:
                    avg_rtt = sum(current_rtts) / len(current_rtts) if current_rtts else 0.0
                    
                    log_entries.append({
                        "domain": current_domain,
                        "resolved_ip": complete_match.group(2),
                        "total_time_s": float(complete_match.group(3)),
                        "servers_visited": int(complete_match.group(4)),
                        "avg_rtt_s": avg_rtt
                    })
                    current_domain = None
                    current_rtts = []

    except FileNotFoundError:
        print(f"Error: Log file not found at '{log_path}'")
        return pd.DataFrame()
    except Exception as e:
        print(f"Error parsing file: {e}")
        return pd.DataFrame()

    return pd.DataFrame(log_entries)

def generate_graphs(data):
    data = data.head(10)
    
    data_servers = data.sort_values(by='servers_visited', ascending=False)
    plt.figure(figsize=(10, 6))
    plt.bar(data_servers["domain"], data_servers["servers_visited"], color="#4C72B0", width=0.6)
    plt.ylabel("DNS Servers Visited")
    plt.title("Total Number of DNS Servers Visited per Domain (First 10)")
    plt.xticks(rotation=45, ha="right")
    plt.grid(axis="y", linestyle=":", alpha=0.7)
    plt.yticks(np.arange(0, data_servers["servers_visited"].max() + 3, 2))
    plt.tight_layout()
    plt.savefig(f"{NAME}_dns_servers_visited.png")

    data_time = data.sort_values(by='total_time_s', ascending=False)
    plt.figure(figsize=(10, 6))
    plt.bar(data_time["domain"], data_time["total_time_s"], color="#55A868", width=0.6)
    plt.ylabel("Total Time (s)")
    plt.title("Total Time to Resolution per Domain (First 10)")
    plt.xticks(rotation=45, ha="right")
    plt.grid(axis="y", linestyle=":", alpha=0.7)
    plt.tight_layout()
    plt.savefig(f"{NAME}_dns_total_time.png")

    data_rtt = data.sort_values(by='avg_rtt_s', ascending=False)
    plt.figure(figsize=(10, 6))
    plt.bar(data_rtt["domain"], data_rtt["avg_rtt_s"], color="#C44E52", width=0.6)
    plt.ylabel("Average RTT (s)")
    plt.title("Average RTT per Query (First 10)")
    plt.xticks(rotation=45, ha="right")
    plt.grid(axis="y", linestyle=":", alpha=0.7)
    plt.tight_layout()
    plt.savefig(f"{NAME}_dns_average_rtt.png")

    print(f"\nPlots saved to {NAME}_dns_servers_visited.png, {NAME}_dns_total_time.png, and {NAME}_dns_average_rtt.png")

def main():
    data = process_resolver_logs(LOG_FILE)
    if data.empty:
        print("No valid resolution records found in log.")
        sys.exit(1)

    print("\nParsed Log Data (Sample of First 10)")
    print(data.head(10).to_string(index=False))

    generate_graphs(data)

    print("\nAggregate Statistics (First 10)")
    print(f"Average Total Time: {data.head(10)['total_time_s'].mean():.3f} s")
    print(f"Average Servers Visited: {data.head(10)['servers_visited'].mean():.2f}")
    print(f"Average RTT: {data.head(10)['avg_rtt_s'].mean():.4f} s")

if __name__ == "__main__":
    for NAME in ["h1", "h2", "h3", "h4"]:
        LOG_FILE = f"{NAME}_results.log"
        main()
