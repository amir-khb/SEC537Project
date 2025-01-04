import time
import logging
from multiprocessing import Process, Queue, Value, Lock
import threading
from urlscan_scraper import (
    setup_logging,
    url_producer,
    verdict_consumer,
    progress_monitor
)


def main():
    setup_logging()

    # Shared resources
    url_queue = Queue()
    backlog_count = Value('i', 0)
    backlog_lock = Lock()
    stop_flag = Value('i', 0)

    # File paths
    output_file = "urlscan_results.json"
    verdicts_file = "urlscan_verdicts.json"

    try:
        # Start producer process
        producer = Process(target=url_producer,
                           args=(url_queue, backlog_count, backlog_lock, stop_flag))
        producer.start()

        # Start consumer processes
        consumers = []
        num_consumers = 3  # Adjust based on your needs
        for _ in range(num_consumers):
            consumer = Process(target=verdict_consumer,
                               args=(url_queue, backlog_count, backlog_lock, stop_flag,
                                     output_file, verdicts_file))
            consumer.start()
            consumers.append(consumer)

        # Start progress monitor in a separate thread
        progress_thread = threading.Thread(target=progress_monitor,
                                           args=(backlog_count, backlog_lock, stop_flag))
        progress_thread.daemon = True
        progress_thread.start()

        # Run for 24 hours
        time.sleep(24 * 60 * 60)

    except KeyboardInterrupt:
        logging.info("Stopping scraper...")
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
    finally:
        # Signal processes to stop
        stop_flag.value = 1

        # Wait for processes to finish
        producer.join()
        for consumer in consumers:
            consumer.join()


if __name__ == "__main__":
    main()