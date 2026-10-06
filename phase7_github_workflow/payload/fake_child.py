"""Fixed synthetic worker/consumer. No descendants or live measurement reads."""
import os
from pathlib import Path
import select
import signal
import sys


def main(args):
    if len(args) != 5:
        return 64
    mode, ready_text, input_text, output_text, ttl_text = args
    if mode not in {'cooperative', 'ignore_term', 'normal', 'stall', 'unavailable', 'no_ready', 'bad_result', 'oversize_result'}:
        return 64
    ready, input_fd, output_fd, ttl = map(int, (ready_text, input_text, output_text, ttl_text))
    if ready < 0 or ttl not in (1, 5):
        return 64
    signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
    signal.alarm(ttl)  # Independent of TERM; backup only, not timely closure proof.
    if mode in {'ignore_term', 'stall', 'no_ready'}:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    decoder = None
    if mode in {'normal', 'bad_result', 'oversize_result'}:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import transport_adapter as transport
        decoder = transport.Decoder()
    if mode == 'unavailable':
        os.close(input_fd); os.close(output_fd)
    if mode != 'no_ready':
        os.write(ready, b'R')
    os.close(ready)
    if mode == 'unavailable':
        return 0
    if decoder is None:
        while True:
            signal.pause()
    input_eof = False
    while True:
        if not select.select([input_fd], [], [], .05)[0]:
            continue
        try:
            chunk = os.read(input_fd, transport.FRAME_CAP)
        except BlockingIOError:
            continue
        if not chunk:
            input_eof = True
            break
        decoder.feed(chunk)
        if decoder.error is not None:
            break
    packet = decoder.finish(input_eof=input_eof)
    if mode == 'bad_result':
        packet = b'\x00\x00\x00\x02{}'
    elif mode == 'oversize_result':
        # Deliberate malformed output fixture. Each write is <= PIPE_BUF;
        # this branch tests a receiver's total bound, not normal result policy.
        for part in (b'x' * transport.RESULT_CAP, b'x'):
            try:
                os.write(output_fd, part)
            except OSError:
                pass
        return 0
    if len(packet) > transport.RESULT_CAP or len(packet) > os.fpathconf(output_fd, 'PC_PIPE_BUF'):
        return 65
    try:
        os.write(output_fd, packet)  # One application offer; no retry/ack.
    except OSError:
        pass
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
