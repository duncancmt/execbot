import time

from collections import deque

from blocking import *

BUF_MAX = 4096

class PipeProc(BlockingProc):
    def __init__(self, *args, **kwargs):
        self.inbuf = deque()
        self.inpos = None
        self.outbuf = []
        self.outsiz = 0
        self.errbuf = []
        self.errsiz = 0
        super(PipeProc, self).__init__(*args, **kwargs)

    def put(self, s):
        if not self.inbuf:
            assert self.inpos == None
            self.inpos = 0
        self.inbuf.append(s)

    def get(self):
        ret = ("".join(self.outbuf) if self.outbuf else None,
               "".join(self.errbuf) if self.errbuf else None)
        self.outbuf = []
        self.errbuf = []
        return ret

    @can_block
    def do_ll_os__ll_os_read(self, fd, size):
        if fd == 0:
            while not self.inbuf:
                yield
            ret = []
            while size:
                buf = self.inbuf[0]
                start = self.inpos
                end = self.inpos + size
                if start == 0:
                    if end >= len(buf):
                        size -= len(buf)
                        ret.append(buf)
                        self.inbuf.popleft()
                        if self.inbuf:
                            self.inpos = 0
                        else:
                            self.inpos = None
                    else:
                        size = 0
                        ret.append(buf[:end])
                        self.inpos = end
                else:
                    if end >= len(buf):
                        size -= len(buf) - start
                        ret.append([start:])
                        if self.inbuf:
                            self.inpos = 0
                        else:
                            self.inpos = None
                    else:
                        size = 0
                        ret.append([start:end])
                        self.inpos = end
            ret = "".join(ret)
            yield ret
        else:
            raise OSError("trying to read from fd %d" % (fd,))

    def do_ll_os__ll_os_write(self, fd, data):
        if fd == 1:
            if self.outsiz == BUF_MAX:
                return 0
            ret = min(len(data), BUF_MAX - self.outsiz)
            self.outsiz += ret
            if ret == len(data):
                self.outbuf.append(data)
            else:
                self.outbuf.append(data[:ret])
            return ret
        if fd == 2:
            if self.errsiz == BUF_MAX:
                return 0
            ret = min(len(data), BUF_MAX - self.errsiz)
            self.errsiz += ret
            if ret == len(data):
                self.errbuf.append(data)
            else:
                self.errbuf.append(data[:ret])
            return ret
        raise OSError("trying to write to fd %d" % (fd,))



    # shamelessly copied from pypy's sandlib

    def do_ll_time__ll_time_sleep(self, seconds):
        # regularly check for timeouts that could have killed the
        # subprocess
        while seconds > 5.0:
            time.sleep(5.0)
            seconds -= 5.0
            if self.poll() is not None:   # subprocess finished?
                return
        time.sleep(seconds)

    def do_ll_time__ll_time_time(self):
        return time.time()

    def do_ll_time__ll_time_clock(self):
        # measuring the CPU time of the controller process has
        # not much meaning, so let's emulate this and return
        # the real time elapsed since the first call to clock()
        # (this is one of the behaviors allowed by the docs)
        try:
            starttime = self.starttime
        except AttributeError:
            starttime = self.starttime = time.time()
        return time.time() - starttime


__all__ = ['PipeProc']
