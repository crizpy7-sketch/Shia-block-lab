"""Fixed one-call resolver entrypoint. No lookup occurs on import."""
import math
import os
import socket
import sys
import time

HOST = 'michel-pr20-377eb54-2-24-81-191.sslip.io'
IP = '2.24.81.191'


def main():
    # This fixed helper is launched only after parent-death protection, stdio
    # isolation, inherited-FD closure and the original-deadline timer are set.
    if len(sys.argv) != 4 or sys.argv[1] != '--resolve-once':
        return 126
    try:
        parent = int(sys.argv[2])
        deadline = float(sys.argv[3])
        if parent <= 1 or os.getppid() != parent or not math.isfinite(deadline) or time.monotonic() >= deadline:
            return 126
        values = socket.getaddrinfo(HOST, 443, socket.AF_INET,
                                    socket.SOCK_STREAM, socket.IPPROTO_TCP)
        valid = type(values) is list and 0 < len(values) <= 64 and all(
            type(row) is tuple and len(row) == 5 and row[0] == socket.AF_INET
            and row[1] == socket.SOCK_STREAM and row[2] == socket.IPPROTO_TCP
            and type(row[4]) is tuple and len(row[4]) == 2
            and row[4] == (IP, 443) for row in values)
        output = b'OK\n' if valid else b'MISMATCH\n'
    except Exception:
        output = b'ERROR\n'
    try:
        if time.monotonic() >= deadline:
            return 126
        return 0 if os.write(1, output) == len(output) else 126
    except Exception:
        return 126


if __name__ == '__main__':
    raise SystemExit(main())
