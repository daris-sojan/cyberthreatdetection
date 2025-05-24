import time

class LogWatcher:
    def __init__(self, filepath):
        self.filepath = filepath

    def watch(self):
        with open(self.filepath, "r") as f:
            f.seek(0, 2)  # Move to end of file
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)  # Wait briefly before checking again
                    continue
                yield line
