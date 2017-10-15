
# -*- coding: utf-8 -*-

class Logger(object):
    """Logger for all of the stuff."""
    def __init__(self, arg):
        super(Logger, self).__init__()
        self.file = arg
        self._openfile()

    def _openfile(self):
        try:
            self.file = open(self.file, "w")
        except:
            print("[Error]: Opening logging file")
            exit(-1)

    def write(self, *args):
        self.file.write(*args)
        self.file.write("\n")

    def success(self, *args):
        self.file.write("[\033[1;32m•\033[00m] {}".format(*args))
        self.file.write("\n")

    def critical(self, *args):
        self.file.write("[\033[1;31m•\033[00m] {}".format(*args))
        self.file.write("\n")
