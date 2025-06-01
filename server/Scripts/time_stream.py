import time
import datetime
from common_utils import stream_log

def time_stream_log_generator(logs=None, count=5, delay=1):
    if logs is None:
        logs = []
    for i in range(count):
        now = datetime.datetime.now().strftime('%H:%M:%S')
        yield from stream_log(logs, f"Current time: {now}")
        time.sleep(delay)
    yield from stream_log(logs, "[SSE test complete]")
    return logs
