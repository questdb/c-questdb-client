#!/usr/bin/env bash
# Runs ON a box. Shapes THIS box's egress traffic *to the peer only*
# so the SSM management path stays unshaped. Symmetric channel: run with the
# same arguments on both boxes; pass HALF the target RTT as --delay-ms to each.
#
#   box_channel.sh set [--rate 2.5gbit] [--delay-ms 10]
#   box_channel.sh clear
#   box_channel.sh status
#   box_channel.sh verify        (client box only: ping + iperf3 to the peer)
set -euo pipefail

PEER="${QNB_PEER_IP:?QNB_PEER_IP not set (ssmx exports it)}"
IFACE=$(ip route get "$PEER" | grep -oP 'dev \K\S+')

clear_qdisc() { tc qdisc del dev "$IFACE" root 2>/dev/null || true; }

case "${1:?set|clear|status|verify}" in
    set)
        shift
        RATE=""; DELAY=""
        while [ $# -gt 0 ]; do
            case "$1" in
                --rate) RATE="$2"; shift 2 ;;
                --delay-ms) DELAY="$2"; shift 2 ;;
                *) echo "unknown arg $1" >&2; exit 1 ;;
            esac
        done
        clear_qdisc
        if [ -z "$RATE" ] && [ -z "$DELAY" ]; then
            echo "nothing to set"; exit 0
        fi
        # htb: default class 1:30 unshaped, class 1:10 shaped; peer traffic -> 1:10
        tc qdisc add dev "$IFACE" root handle 1: htb default 30
        tc class add dev "$IFACE" parent 1: classid 1:30 htb rate 100gbit
        tc class add dev "$IFACE" parent 1: classid 1:10 htb \
            rate "${RATE:-100gbit}" ceil "${RATE:-100gbit}"
        if [ -n "$DELAY" ]; then
            # limit sized for ~BDP at 10 Gbps x delay to avoid netem drops
            tc qdisc add dev "$IFACE" parent 1:10 handle 10: \
                netem delay "${DELAY}ms" limit 100000
        fi
        tc filter add dev "$IFACE" protocol ip parent 1: prio 1 \
            u32 match ip dst "$PEER"/32 flowid 1:10
        echo "channel set: rate=${RATE:-unshaped} delay=${DELAY:-0}ms -> $PEER on $IFACE"
        ;;
    clear)
        clear_qdisc
        echo "channel cleared on $IFACE"
        ;;
    status)
        ip link show "$IFACE" | head -1
        tc -s qdisc show dev "$IFACE"
        ;;
    verify)
        echo "== MTU"; ip link show "$IFACE" | grep -oP 'mtu \K\d+'
        echo "== RTT"; ping -c 10 -q "$PEER" | tail -2
        echo "== iperf3 single flow (gate: >= 9 Gbps unshaped in the placement group)"
        iperf3 -c "$PEER" -t 10 -O 2 | tail -4
        echo "== iperf3 4 flows"
        iperf3 -c "$PEER" -t 10 -O 2 -P 4 | tail -4
        ;;
    *)
        echo "unknown mode" >&2; exit 1 ;;
esac
