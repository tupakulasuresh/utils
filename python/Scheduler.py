import logging
import time
from threading import Thread
import queue
from sys import exc_info
from traceback import format_exc

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s')
logging.basicConfig(format='%(levelname)s: %(message)s')
LOG = logging.getLogger(__name__)


class Scheduler(object):
    '''
    This uses pool of worker threads to process all tasks in the queue
    workes are configurable, and gives flexibility to deal with more tasks
    Scaling threads is not a optimal solution as this will not achieve parallelization
    due to limitation of processor resources and nature of GIL

    Instead, this library implements as a pool of workers taking up new task after
    completing its current task
    '''

    _MAX_WORKERS = 8

    def __init__(self, size=None):
        self.iqueue = queue.Queue()
        self.oqueue = queue.Queue()
        self.worker_threads = list()
        self.task_id = 1

        if not size:
            size = self._MAX_WORKERS

        for _ in range(size):
            self.add_worker()

    def set_max_workers_count(self, count):
        self._MAX_WORKERS = count

    @property
    def max_workers(self):
        return self._MAX_WORKERS

    @property
    def workers(self):
        return len(self.worker_threads)

    def reset_task_id(self):
        self.task_id = 1

    def add_worker(self):
        assert self.workers <= self._MAX_WORKERS, \
                "Reached max workers {}".format(self._MAX_WORKERS)
        worker = Worker(self.iqueue, self.oqueue, name='worker-{}'.format(self.workers + 1))
        worker.daemon = True
        worker.start()
        self.worker_threads.append(worker)

    def remove_worker(self):
        assert self.workers, "No workers to remove"
        worker = self.worker_threads.pop()
        del worker

    def add_task(self, cmd, args=None, kwargs=None, name=None):
        args = tuple() if args is None else args
        kwargs = dict() if kwargs is None else kwargs
        name = name if name else self.task_id

        task = (cmd, args, kwargs)

        self.iqueue.put((str(name),) + task)
        self.task_id += 1

    def run(self, tasks):
        # flush output queue to remove previously collected data
        self.flush_output_queue()

        for _id, task in enumerate(tasks, start=1):
            cmd, args, kwargs = task
            self.add_task(cmd, args, kwargs, name=_id)

    def wait_for_completion(self, get_outcome=True):
        start_time = time.time()
        LOG.debug("Waiting for tasks to complete ...")
        self.iqueue.join()
        LOG.debug("Took %ds for completion", int(time.time() - start_time))
        if get_outcome:
            output = self.retrieve_output()
        else:
            output = None
        return output

    def flush_output_queue(self):
        while True:
            try:
                self.oqueue.get()
            except queue.Empty:
                pass
        self.reset_task_id()

    def flush_input_queue(self):
        while True:
            try:
                self.iqueue.get()
            except queue.Empty:
                pass

    def retrieve_output(self):
        output = {}
        while True:
            try:
                status = self.oqueue.get_nowait()
                if len(status) == 2:
                    (_id, ret_val) = status
                    output.update({_id: ret_val})
                else:
                    (_id, _, trace) = status
                    output.update({_id: trace})
            except queue.Empty:
                break
        self.reset_task_id()
        return output


class Worker(Thread):

    def __init__(self, iqueue, oqueue, *args, **kwargs):
        self.iqueue = iqueue
        self.oqueue = oqueue
        super(Worker, self).__init__(*args, **kwargs)

    def run(self):
        while True:
            _id, cmd, _args, _kwargs = self.iqueue.get()
            LOG.debug("Got id=%s, cmd=%s, args=%s, kwargs=%s", _id, cmd.__name__, _args, _kwargs)
            try:
                if _args and _kwargs:
                    output = cmd(*_args, **_kwargs)
                elif _args:
                    output = cmd(*_args)
                elif _kwargs:
                    output = cmd(**_kwargs)
                else:
                    output = cmd()
                self.oqueue.put((_id, output))
            except Exception as e:
                self.oqueue.put((_id, e, format_exc(exc_info()[-1])))
            finally:
                self.iqueue.task_done()
