import logging
import random
import time
from Scheduler import Scheduler

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
LOG = logging.getLogger(__name__)

def dummy_test():
    wait = random.randint(0, 4)
    LOG.debug("waiting for %d seconds", wait)
    time.sleep(float(wait))
    return wait


def run():
    s = Scheduler()
    for i in range(1, 11):
        s.add_task(dummy_test, (), {}, name='task_{}'.format(i))
    output = s.wait_for_completion()
    LOG.debug("Total wait from individual threads %d", sum(output.values()))
    print output

if __name__ == '__main__':
    run()
