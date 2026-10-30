#!/usr/bin/env python3
"""Mininet/OVS topology with three transparent Docker VNFs.

Run as root on a Linux host with Mininet, OVS, Docker, iproute2 and nsenter.
Build the firewall, IDS and policer images first. Each image waits for
/run/sfc-ready, then starts /app/start.sh with Docker-managed logs.

Fixed OpenFlow ports (also defined in sfc_controller.py):
  s1: 1=h1, 2=s2, 3/4=firewall, 5/6=IDS, 7/8=policer
  s2: 1=s1, 2=h2
Each VNF has eth0 for controller management and eth1/eth2 for data.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from mininet.cli import CLI
from mininet.link import Link
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController


DPID_S1 = "0000000000000001"
DPID_S2 = "0000000000000002"
VNFS = (
    ("sfc-fw", "sfc-firewall:latest", (("sfw-in", "sfw-ip", "eth1", 3),
                                        ("sfw-out", "sfw-op", "eth2", 4))),
    ("sfc-ids", "sfc-ids:latest", (("sid-in", "sid-ip", "eth1", 5),
                                    ("sid-out", "sid-op", "eth2", 6))),
    ("sfc-pol", "sfc-policer:latest", (("spol-in", "spol-ip", "eth1", 7),
                                       ("spol-out", "spol-op", "eth2", 8))),
)


def run(*args):
    """Run a host command and include its stderr in a failure."""
    try:
        return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"{' '.join(args)} failed: {exc.stderr.strip()}") from exc


def in_container(pid, *args):
    """Use host iproute2 in a Docker network namespace."""
    return run("nsenter", "-t", str(pid), "-n", *args)


def require_environment():
    if os.geteuid() != 0:
        raise RuntimeError("Run sfc_topology.py as root (sudo -E python3 ...).")
    for binary in ("docker", "ip", "nsenter", "ovs-vsctl", "ovs-ofctl"):
        if not shutil.which(binary):
            raise RuntimeError(f"Missing required command: {binary}")
    if not os.environ.get("SFC_API_TOKEN"):
        raise RuntimeError("Set SFC_API_TOKEN (run_demo.sh does this automatically).")
    for name, image, links in VNFS:
        if subprocess.run(("docker", "container", "inspect", name),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            raise RuntimeError(f"Container {name} already exists; remove it before starting.")
        if subprocess.run(("docker", "image", "inspect", image),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            raise RuntimeError(f"Missing image {image}; build the VNF images first.")
        for host_end, _, _, _ in links:
            if subprocess.run(("ip", "link", "show", host_end),
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                raise RuntimeError(f"Interface {host_end} already exists; clean up stale links.")


def set_and_check_ofport(interface, expected):
    """Verify the controller's port map against the actual OVS assignment."""
    run("ovs-vsctl", "set", "Interface", interface, f"ofport_request={expected}")
    for _ in range(30):
        actual = run("ovs-vsctl", "get", "Interface", interface, "ofport")
        if actual == str(expected):
            return
        time.sleep(0.1)
    raise RuntimeError(f"{interface}: expected OpenFlow port {expected}, got {actual}")


def attach_vnf(switch, name, image, links, created_links, created_containers):
    """Attach a two-port Docker container to s1 as a transparent L2 VNF."""
    command = ["docker", "run", "-d", "--rm", "--network", "bridge",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--name", name]
    if name == "sfc-ids":
        command += ["--cap-add", "NET_RAW",
                    "--add-host", "host.docker.internal:host-gateway",
                    "--env", "SFC_API_TOKEN"]
    elif name == "sfc-fw":
        command += ["--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW"]
    else:
        command += ["--cap-add", "NET_ADMIN"]
    run(*(command + [image]))
    created_containers.append(name)
    pid = int(run("docker", "inspect", "-f", "{{.State.Pid}}", name))
    if pid <= 0:
        raise RuntimeError(f"Container {name} did not start")

    for host_end, peer_end, inside, ofport in links:
        run("ip", "link", "add", host_end, "type", "veth", "peer", "name", peer_end)
        created_links.append(host_end)
        run("ip", "link", "set", peer_end, "netns", str(pid))
        in_container(pid, "ip", "link", "set", peer_end, "name", inside)
        run("ovs-vsctl", "--", "add-port", switch, host_end,
            "--", "set", "Interface", host_end, f"ofport_request={ofport}")
        run("ip", "link", "set", host_end, "up")
        set_and_check_ofport(host_end, ofport)

    # eth0 stays on Docker's management bridge. Only eth1/eth2 join br0,
    # keeping alert traffic separate from the OpenFlow data path.
    in_container(pid, "ip", "link", "add", "br0", "type", "bridge")
    in_container(pid, "ip", "link", "set", "br0", "up")
    for _, _, inside, _ in links:
        in_container(pid, "ip", "link", "set", inside, "master", "br0")
        in_container(pid, "ip", "link", "set", inside, "up")
    in_container(pid, "ip", "link", "set", "lo", "up")
    run("docker", "exec", name, "test", "-x", "/app/start.sh")
    run("docker", "exec", name, "touch", "/run/sfc-ready")
    for _ in range(30):
        active = subprocess.run(("docker", "exec", name, "test", "-f", "/run/sfc-active"),
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL).returncode == 0
        if active:
            if run("docker", "inspect", "-f", "{{.State.Running}}", name) != "true":
                break
            info(f"*** Started {name}: {links[0][0]} -> {links[1][0]}\n")
            return
        time.sleep(0.1)
    raise RuntimeError(f"{name} did not become healthy; inspect docker logs")


def start_demo_servers(h2, servers):
    """Listen on chained 80, trusted 8080, and firewall-blocked 23."""
    server_script = str(Path(__file__).resolve().with_name("demo_http_server.py"))
    for port in (80, 8080, 23):
        process = h2.popen(["python3", server_script, str(port)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        servers.append(process)
    time.sleep(0.3)
    if any(process.poll() is not None for process in servers):
        raise RuntimeError("An h2 demo HTTP server failed to start")


def wait_for_controller():
    """Do not advertise a ready topology until both switches have rules."""
    for _ in range(50):
        s1_flows = run("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1")
        s2_flows = run("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s2")
        if "priority=200" in s1_flows and "priority=10" in s2_flows:
            return
        time.sleep(0.1)
    raise RuntimeError("Controller rules did not arrive on both switches within 5 seconds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6633)
    args = parser.parse_args()
    require_environment()
    setLogLevel("info")

    net = Mininet(build=False, controller=None, switch=OVSSwitch, link=Link,
                  autoSetMacs=False)
    created_links = []
    created_containers = []
    servers = []
    try:
        net.addController("c0", controller=RemoteController,
                          ip=args.controller_ip, port=args.controller_port)
        h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        s1 = net.addSwitch("s1", dpid=DPID_S1, protocols="OpenFlow13",
                           failMode="secure")
        s2 = net.addSwitch("s2", dpid=DPID_S2, protocols="OpenFlow13",
                           failMode="secure")
        net.addLink(h1, s1, port1=0, port2=1)
        net.addLink(s1, s2, port1=2, port2=1)
        net.addLink(s2, h2, port1=2, port2=0)
        net.start()

        for interface, ofport in (("s1-eth1", 1), ("s1-eth2", 2),
                                  ("s2-eth1", 1), ("s2-eth2", 2)):
            set_and_check_ofport(interface, ofport)
        for name, image, links in VNFS:
            attach_vnf("s1", name, image, links, created_links, created_containers)
        wait_for_controller()
        start_demo_servers(h2, servers)

        info("*** Ready. Try: h1 ping -c 1 10.0.0.2\n")
        info("*** Chained: h1 curl http://10.0.0.2:80/\n")
        info("*** Trusted: h1 curl http://10.0.0.2:8080/\n")
        info("*** IDS alert: h1 curl http://10.0.0.2/attack\n")
        info("*** Upload test: h1 python3 demo_client.py upload --port 80\n")
        info("*** Dashboard: http://127.0.0.1:8080/sfc\n")
        CLI(net)
    finally:
        for process in servers:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        for name in reversed(created_containers):
            subprocess.run(("docker", "rm", "-f", name),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for host_end in reversed(created_links):
            subprocess.run(("ip", "link", "delete", host_end),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        net.stop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Topology error: {exc}", file=sys.stderr)
        sys.exit(1)
