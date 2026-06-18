import queue
import logging
import threading
import typing
from time import sleep
from contextlib import suppress


class SpiderFootThreadPool:
    """
    Each thread in the pool is spawned only once, and reused for best performance.

    Example 1: using foreach()
        with SpiderFootThreadPool(self.opts["_maxthreads"]) as pool:
            # callback("a", "arg1"), callback("b", "arg1"), ...
            for result in pool.foreach(
                    callback,
                    ["a", "b", "c", "d"],
                    "arg1",
                    taskName="sfp_testmodule"
                    saveResult=True
                ):
                yield result

    Example 2: using submit()
        with SpiderFootThreadPool(self.opts["_maxthreads"]) as pool:
            pool.start()
            # callback("arg1"), callback("arg2")
            pool.submit(callback, "arg1", taskName="sfp_testmodule", saveResult=True)
            pool.submit(callback, "arg2", taskName="sfp_testmodule", saveResult=True)
            for result in pool.shutdown()["sfp_testmodule"]:
                yield result
    """

    # Maximum iterations to wait for workers (each iteration ~100ms)
    _WAIT_TIMEOUT = 300  # ~30 seconds

    def __init__(self, threads: int = 100, qsize: int = 10, name: str = '') -> None:
        """Initialize the SpiderFootThreadPool class.

        Args:
            threads (int): Max number of threads
            qsize (int): Queue size
            name (str): Name
        """
        self.log = logging.getLogger(f"spiderfoot.{__name__}")
        self.threads = int(threads)
        self.qsize = int(qsize)
        self.pool = [None] * self.threads
        self.name = str(name)
        self.inputThread = None
        self.inputQueues = dict()
        self.outputQueues = dict()
        self._stop = False
        self._lock = threading.Lock()

    def start(self) -> None:
        self.log.debug(f'Starting thread pool {self.name!r} with {self.threads:,} threads')
        for i in range(self.threads):
            t = ThreadPoolWorker(pool=self, name=f"{self.name}_worker_{i + 1}")
            t.start()
            self.pool[i] = t

    @property
    def stop(self) -> bool:
        return self._stop

    @stop.setter
    def stop(self, val: bool):
        assert val in (True, False), "stop must be either True or False"
        for t in self.pool:
            with suppress(Exception):
                t.stop = val
        self._stop = val

    def _join_input_thread(self) -> None:
        """Join the feedQueue input thread without signaling workers to stop."""
        if self.inputThread is not None:
            self.inputThread.join(timeout=5)

    def _stop_workers(self) -> None:
        """Signal all workers to stop.

        Sets _stop to True (bypassing the setter to avoid propagating to
        workers via the setter loop), then sets t.stop = True on each worker.
        """
        self._stop = True
        for t in self.pool:
            with suppress(Exception):
                if t is not None:
                    t.stop = True

    def _wait_for(self, check: typing.Callable[[], bool]) -> None:
        """Poll until check() returns True or timeout expires.

        Args:
            check: A callable that returns True when the desired condition
                   has been met.
        """
        for _ in range(self._WAIT_TIMEOUT):
            if check():
                break
            sleep(.1)

    def shutdown(self, wait: bool = True) -> dict:
        """Shut down the pool.

        Args:
            wait (bool): Whether to wait for the pool to finish executing

        Returns:
            results (dict): (unordered) results in the format: {"taskName": [returnvalue1, returnvalue2, ...]}
        """
        results = dict()
        self.log.debug(f'Shutting down thread pool {self.name!r} with wait={wait}')
        if wait:
            while not self.finished and not self.stop:
                with self._lock:
                    outputQueues = list(self.outputQueues)
                for taskName in outputQueues:
                    moduleResults = list(self.results(taskName))
                    try:
                        results[taskName] += moduleResults
                    except KeyError:
                        results[taskName] = moduleResults
                sleep(.1)
        # Stop the input thread (without signaling workers)
        self._join_input_thread()
        # Wait for all workers to finish their current tasks (up to ~30s)
        idle_count = 0
        while any(t.busy for t in self.pool if t is not None):
            sleep(.1)
            idle_count += 1
            if idle_count >= self._WAIT_TIMEOUT:
                break
        # Now signal workers to stop
        self._stop_workers()
        # make sure input queues are empty
        with self._lock:
            inputQueues = list(self.inputQueues.values())
        for q in inputQueues:
            with suppress(Exception):
                while 1:
                    q.get_nowait()
            with suppress(Exception):
                q.close()
        # make sure output queues are empty
        with self._lock:
            outputQueues = list(self.outputQueues.items())
        for taskName, q in outputQueues:
            moduleResults = list(self.results(taskName))
            try:
                results[taskName] += moduleResults
            except KeyError:
                results[taskName] = moduleResults
            with suppress(Exception):
                q.close()
        return results

    def submit(self, callback, *args, **kwargs) -> None:
        """Submit a function call to the pool.
        The "taskName" and "maxThreads" arguments are optional.

        Args:
            callback (function): callback function
            *args: Passed through to callback
            **kwargs: Passed through to callback, except for taskName and maxThreads
        """
        taskName = kwargs.get('taskName', 'default')
        maxThreads = kwargs.pop('maxThreads', 100)
        # block if this module's thread limit has been reached
        while self.countQueuedTasks(taskName) >= maxThreads and not self.stop:
            sleep(.01)
            continue
        self.log.debug(
            f"Submitting {callback.__name__!r} from "
            f"module {taskName!r} to pool {self.name!r}"
        )
        self.inputQueue(taskName).put((callback, args, kwargs))

    def countQueuedTasks(self, taskName: str) -> int:
        """For the specified task, returns the number of queued function calls
        plus the number of functions which are currently executing

        Args:
            taskName (str): Name of task

        Returns:
            int: the number of queued function calls plus the number of functions which are currently executing
        """
        queuedTasks = 0
        with suppress(Exception):
            queuedTasks += self.inputQueues[taskName].qsize()
        runningTasks = 0
        for t in self.pool:
            with suppress(Exception):
                if t.taskName == taskName:
                    runningTasks += 1
        return queuedTasks + runningTasks

    def inputQueue(self, taskName: str = "default") -> queue.Queue:
        try:
            return self.inputQueues[taskName]
        except KeyError:
            self.inputQueues[taskName] = queue.Queue(self.qsize)
            return self.inputQueues[taskName]

    def outputQueue(self, taskName: str = "default") -> queue.Queue:
        try:
            return self.outputQueues[taskName]
        except KeyError:
            self.outputQueues[taskName] = queue.Queue(self.qsize)
            return self.outputQueues[taskName]

    def foreach(self, callback, iterable, *args, **kwargs) -> typing.Iterator[typing.Any]:
        """Map callback over iterable across worker threads.

        Args:
            callback: the function to thread
            iterable: each entry will be passed as the first argument to the function
            args: additional arguments to pass to callback function
            kwargs: keyword arguments to pass to callback function

        Yields:
            return values from completed callback function
        """
        taskName = kwargs.get("taskName", "default")

        # Reset pool state if it was previously shut down
        if self._stop:
            # Wait for old workers to fully exit before clearing queues.
            # The finally block set stop=True, so workers will finish their
            # current task and exit their run loop. We must wait for them
            # to die, not just become idle, to avoid old workers writing
            # to queues that the reset block is about to clear.
            if any(t is not None and t.is_alive() for t in self.pool):
                self._wait_for(lambda: all(t is None or not t.is_alive() for t in self.pool))
            self.pool = [None] * self.threads
            self._stop = False
            self.inputQueues.clear()
            self.outputQueues.clear()
        else:
            # Restart any dead workers (crashed threads remain in the pool list)
            for i, t in enumerate(self.pool):
                if t is not None and not t.is_alive():
                    self.pool[i] = ThreadPoolWorker(pool=self, name=f"{self.name}_worker_{i + 1}")
                    self.pool[i].start()

        self.inputThread = threading.Thread(target=self.feedQueue, args=(callback, iterable, args, kwargs))
        self.inputThread.start()

        # Start workers if none have been created yet
        if self.pool[0] is None:
            self.start()

        sleep(.1)
        try:
            yield from self.results(taskName, wait=True)
        finally:
            # Ensure cleanup: stop feedQueue and workers, then wait for them to finish
            self._join_input_thread()
            self._stop_workers()

    def results(self, taskName: str = "default", wait: bool = False) -> typing.Iterator[typing.Any]:
        while 1:
            result = False
            with suppress(Exception):
                while 1:
                    yield self.outputQueue(taskName).get_nowait()
                    result = True
            if self.countQueuedTasks(taskName) == 0 or not wait:
                break
            if not result:
                # sleep briefly to save CPU
                sleep(.1)

    def feedQueue(self, callback, iterable, args, kwargs) -> None:
        for i in iterable:
            if self.stop:
                break
            self.submit(callback, i, *args, **kwargs)

    @property
    def finished(self) -> bool:
        if self.stop:
            return True
        finishedThreads = [not t.busy for t in self.pool if t is not None]
        try:
            inputThreadAlive = self.inputThread.is_alive()
        except AttributeError:
            inputThreadAlive = False

        inputQueuesEmpty = [q.empty() for q in self.inputQueues.values()]
        return not inputThreadAlive and all(inputQueuesEmpty) and all(finishedThreads)

    def __enter__(self) -> "SpiderFootThreadPool":
        return self

    def __exit__(self, exception_type, exception_value, traceback) -> None:
        self.shutdown()


class ThreadPoolWorker(threading.Thread):

    def __init__(self, pool, name: str = None) -> None:

        self.log = logging.getLogger(f"spiderfoot.{__name__}")
        self.pool = pool
        self.taskName = ""  # which module submitted the callback
        self.busy = False
        self.stop = False

        super().__init__(name=name)

    def run(self) -> None:
        # Round-robin through each module's input queue
        while not self.stop:
            ran = False
            with self.pool._lock:
                inputQueues = list(self.pool.inputQueues.values())
            for q in inputQueues:
                if self.stop:
                    break
                try:
                    self.busy = True
                    callback, args, kwargs = q.get_nowait()
                    self.taskName = kwargs.pop("taskName", "default")
                    saveResult = kwargs.pop("saveResult", False)
                    try:
                        result = callback(*args, **kwargs)
                        ran = True
                    except Exception:  # noqa: B902
                        import traceback
                        self.log.error(f'Error in thread worker {self.name}: {traceback.format_exc()}')
                        break
                    if saveResult:
                        self.pool.outputQueue(self.taskName).put(result)
                except queue.Empty:
                    self.busy = False
                finally:
                    self.busy = False
                    self.taskName = ""
            # sleep briefly to save CPU
            if not ran:
                sleep(.05)
