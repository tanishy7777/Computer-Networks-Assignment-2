import socket
from scapy.all import DNS, raw, DNSRR, DNSQR
import time
from datetime import datetime
import threading

ROOT_SERVER_IP = "198.41.0.4"
LOG_MUTEX = threading.Lock()
RESOLVER_IP = '10.0.0.5'
RESOLVER_PORT = 53
LOG_FILE_NAME = 'resolver_events.log'
NETWORK_TIMEOUT = 5

QUERY_COUNT = 0
QUERY_MUTEX = threading.Lock()

ACTIVE_TIME = 0.0  # total time spent processing queries (excluding throttle)
ACTIVE_TIME_MUTEX = threading.Lock()

THROTTLE_LOCK = threading.Lock()  # used to block new queries when throttling
THROTTLED = False  # indicates if we’re in throttle mode


def log_event(query_log, message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    log_line = f"[{timestamp}] {message}"
    print(log_line)
    query_log.append(log_line)

def send_query(sock, packet, ip):
    try:
        sock.sendto(raw(packet), (str(ip), 53))
        data, _ = sock.recvfrom(4096)
        return DNS(data)
    except:
        return None

def get_additional_records(response):
    ips = []
    for i in range(response.arcount):
        record = response.ar[i]
        if record.type == 1:
            ips.append(record.rdata)
    return ips

def perform_iterative_resolution(sock, query_pkt, query_log, servers_visited, depth=0, domain_name=None, start_time=None):
    if isinstance(query_pkt, bytes):
        query_pkt = DNS(query_pkt)

    stage_level = [0]
    stage_names = ["Root", "TLD", "Authoritative"]

    if depth == 0:
        domain_name = str(query_pkt.qd.qname.decode() if isinstance(query_pkt.qd.qname, bytes) else query_pkt.qd.qname)
        start_time = time.time()
        log_event(query_log, f"Domain name queried: {domain_name} | Resolution mode: Iterative")

    next_server_ips = [ROOT_SERVER_IP]
    response_pkt = None

    while True:
        resolution_step = stage_names[min(stage_level[0], 2)]
        rtt_start = time.time()
        contacted_ip = next_server_ips[0]

        for ip in next_server_ips:
            servers_visited[0] += 1
            response_pkt = send_query(sock, query_pkt, ip)
            if response_pkt:
                contacted_ip = ip
                break
        
        rtt = time.time() - rtt_start
        
        if response_pkt is None:
            log_event(query_log, f"DNS server IP contacted: {contacted_ip} ({resolution_step}) | Response: FAILED | Round-trip time: {rtt:.6f}s")
            log_event(query_log, f"RESOLUTION_FAILED: {domain_name} | Total time to resolution: {time.time() - start_time:.4f}s")
            return None

        if response_pkt.ancount:
            for record in response_pkt.an:
                if record.type == 1:
                    log_event(query_log, f"DNS server IP contacted: {contacted_ip} ({resolution_step}) | Response or referral received: ANSWER ({record.rdata}) | Round-trip time: {rtt:.6f}s")
                    if depth == 0:
                        total_duration = time.time() - start_time
                        log_event(query_log, f"RESOLUTION_COMPLETE: {domain_name} | IP: {record.rdata} | Total time to resolution: {total_duration:.4f}s | SERVERS_VISITED: {servers_visited[0]}")
                    return record.rdata
                
                elif record.type == 5:
                    cname_target = record.rdata.decode()
                    log_event(query_log, f"DNS server IP contacted: {contacted_ip} ({resolution_step}) | Response or referral received: CNAME ({cname_target}) | Round-trip time: {rtt:.6f}s")
                    query_pkt = DNS(qd=DNSQR(qname=cname_target))
                    next_server_ips = [ROOT_SERVER_IP]
                    stage_level = [0]
                    break
            else:
                continue

        elif response_pkt.nscount > 0:
            if response_pkt.ns[0].type == 2:
                referral = response_pkt.ns[0].rdata.decode()
                log_event(query_log, f"DNS server IP contacted: {contacted_ip} ({resolution_step}) | Response or referral received: REFERRAL ({referral}) | Round-trip time: {rtt:.6f}s")
                stage_level[0] += 1
                
                glue_records = get_additional_records(response_pkt)
                if glue_records:
                    next_server_ips = glue_records
                    continue

                new_ns_ips = []
                for i in range(response_pkt.nscount):
                    ns_hostname = response_pkt.ns[i].rdata
                    log_event(query_log, f"Resolving NS record: {ns_hostname.decode()}")

                    ip = perform_iterative_resolution(
                        sock, DNS(qd=DNSQR(qname=ns_hostname)), query_log, 
                        servers_visited, depth + 1, domain_name, start_time
                    )
                    if ip:
                        new_ns_ips.append(ip)

                if not new_ns_ips:
                    log_event(query_log, f"NS resolution failed")
                    log_event(query_log, f"RESOLUTION_FAILED: {domain_name} | Total time to resolution: {time.time() - start_time:.4f}s")
                    return None
                
                next_server_ips = new_ns_ips
            else:
                return None
        else:
            return None

# def dispatch_query(data, client_address, listen_socket):
#     query_log = []
#     servers_visited_count = [0]
#     query_socket = None
    
#     try:
#         query_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         query_socket.settimeout(NETWORK_TIMEOUT)

#         incoming_packet = DNS(data)
#         domain_to_query = incoming_packet.qd[0].qname
#         packet_to_forward = DNS(qd=DNSQR(qname=domain_to_query))

#         final_ip_address = perform_iterative_resolution(query_socket, packet_to_forward, query_log, servers_visited_count)

#         if final_ip_address:
#             reply_packet = DNS(
#                 id=incoming_packet.id, qr=1, aa=0, ra=1, rcode=0,
#                 qd=incoming_packet.qd,
#                 an=DNSRR(rrname=incoming_packet.qd.qname, type='A', ttl=60, rdata=final_ip_address)
#             )
#             listen_socket.sendto(raw(reply_packet), client_address)
#             print(f"[REPLY] {domain_to_query.decode()} -> {final_ip_address} (to {client_address[0]})")

#     except Exception as e:
#         print(f"[WORKER_FAILURE] {e}")

#     finally:
#         if query_socket:
#             query_socket.close()

#         with LOG_MUTEX:
#             with open(LOG_FILE_NAME, 'a') as f:
#                 if not query_log or "RESOLUTION_COMPLETE" not in query_log[-1]:
#                     query_log.append(f"[FINAL_STATE: FAILED]")
#                 f.write("\n".join(query_log) + "\n\n")

def dispatch_query(data, client_address, listen_socket):
    global QUERY_COUNT, ACTIVE_TIME, THROTTLED
    query_log = []
    servers_visited_count = [0]
    query_socket = None

    # Wait if currently throttled
    while True:
        with QUERY_MUTEX:
            if not THROTTLED:
                break
        time.sleep(0.1)  # short wait, prevents spinning

    with QUERY_MUTEX:
        QUERY_COUNT += 1
        current_query_num = QUERY_COUNT

        if current_query_num % 75 == 0:
            print(f"[THROTTLE] 75 queries processed. Sleeping for 60 seconds...")
            THROTTLED = True
            def do_throttle():
                global THROTTLED
                time.sleep(60)
                with QUERY_MUTEX:
                    THROTTLED = False
                print("[THROTTLE] Resuming normal query processing.")
            threading.Thread(target=do_throttle, daemon=True).start()

    start_active = time.time()

    try:
        query_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        query_socket.settimeout(NETWORK_TIMEOUT)

        incoming_packet = DNS(data)
        domain_to_query = incoming_packet.qd[0].qname
        packet_to_forward = DNS(qd=DNSQR(qname=domain_to_query))

        final_ip_address = perform_iterative_resolution(query_socket, packet_to_forward, query_log, servers_visited_count)

        if final_ip_address:
            reply_packet = DNS(
                id=incoming_packet.id, qr=1, aa=0, ra=1, rcode=0,
                qd=incoming_packet.qd,
                an=DNSRR(rrname=incoming_packet.qd.qname, type='A', ttl=60, rdata=final_ip_address)
            )
            listen_socket.sendto(raw(reply_packet), client_address)
            print(f"[REPLY] {domain_to_query.decode()} -> {final_ip_address} (to {client_address[0]})")

    except Exception as e:
        print(f"[WORKER_FAILURE] {e}")

    finally:
        end_active = time.time()
        with ACTIVE_TIME_MUTEX:
            ACTIVE_TIME += (end_active - start_active)

        if query_socket:
            query_socket.close()

        with LOG_MUTEX:
            with open(LOG_FILE_NAME, 'a') as f:
                if not query_log or "RESOLUTION_COMPLETE" not in query_log[-1]:
                    query_log.append(f"[FINAL_STATE: FAILED]")
                f.write("\n".join(query_log) + "\n\n")


def init_resolver():
    main_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    main_socket.bind((RESOLVER_IP, RESOLVER_PORT))
    print(f"Custom resolver active on {RESOLVER_IP}:{RESOLVER_PORT}")

    while True:
        try:
            payload, address = main_socket.recvfrom(4096)
            worker = threading.Thread(
                target=dispatch_query,
                args=(payload, address, main_socket),
                daemon=True
            )
            worker.start()
        except Exception as e:
            print(f'[LISTENER_FAILURE] {e}')

if __name__ == "__main__":
    init_resolver()