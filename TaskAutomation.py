import threading
import time
from Discover import Discover

class TaskAutomation:
    def __init__(self):
        self.tasks = []
        self.mode = 'sequential'
        self.live_monitor_mode = False
        self.modes = {
            'sequential': self._sequential_mode,
            'timed': self._timed_mode,
            'safe': self._safe_mode,
            'hardcore': self._hardcore_mode,
            'focus': self._focus_mode,
            'live_monitor': self._live_monitor_mode,
            'smart': self._smart_mode,
        }
        
        self.PrivateScanner = Discover()
        

    def set_mode(self, mode):
        valid_modes = list(self.modes.keys())
        if mode in valid_modes:
            self.mode = mode
        else:
            raise ValueError(f"Invalid mode. Choose from {', '.join(valid_modes)}")
        

    def create_task(self, task_func, *args, **kwargs):
        task = threading.Thread(target=task_func, args=args, kwargs=kwargs)
        self.tasks.append(task)


    def run_tasks(self, interval=0):
        if self.mode in self.modes:
            if self.mode in ['timed', 'verbose']:  # Modes that require an interval
                self.modes[self.mode](interval)
            else:
                self.modes[self.mode]()
        else:
            raise ValueError(f"Mode {self.mode} not implemented.")
        

    def _sequential_mode(self):
        for task in self.tasks:
            try:
                task.start()
                task.join()
            except Exception as e:
                print(f"[!] Error in task {task.name}: {e}")
                

    def _timed_mode(self, interval):
        for task in self.tasks:
            try:
                task.start()
                task.join()
                time.sleep(interval)
            except Exception as e:
                print(f"[!] Error in task {task.name}: {e}")
                

    def _safe_mode(self, time_sleep=3):
        for task in self.tasks:
            try:
                print(f"Safe mode: Logging task {task.name}")
                time.sleep(time_sleep)
                task.start()
                task.join()
            except Exception as e:
                print(f"[!] Error in task {task.name}: {e}")
                

    def _hardcore_mode(self):
        for task in self.tasks:
            attempts = 0
            while attempts < 3:
                try:
                    task.start()
                    task.join()
                    print(f"Hardcore mode: Task {task.name} completed")
                    break
                except Exception as e:
                    attempts += 1
                    print(f"Hardcore mode: Task {task.name} failed, attempt {attempts}, error: {e}")
                    time.sleep(2)
            if attempts == 3:
                print(f"Hardcore mode: Task {task.name} failed after 3 attempts")
                

    def _focus_mode(self):
        for task in self.tasks:
            try:
                print(f"Focus mode: Starting task {task.name}")
                task.start()
                task.join()
                print(f"Focus mode: Completed task {task.name}")
                time.sleep(5)
            except Exception as e:
                print(f"[!] Error in task {task.name}: {e}")
                

    def _live_monitor_mode(self):
        self.live_monitor_mode = True

        def monitor():
            while self.live_monitor_mode:
                remaining_tasks = len([task for task in self.tasks if task.is_alive()])
                print(f"Live monitor mode: {remaining_tasks} tasks remaining")
                if remaining_tasks == 0:
                    break
                time.sleep(2)

        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.start()

        for task in self.tasks:
            try:
                task.start()
            except Exception as e:
                print(f"[!] Error starting task {task.name}: {e}")

        for task in self.tasks:
            try:
                task.join()
            except Exception as e:
                print(f"[!] Error joining task {task.name}: {e}")

        self.live_monitor_mode = False
        monitor_thread.join()
        

    def _smart_mode(self, delay=5):
        """
        Smart mode: Changes MAC addresses, runs tasks with random delays, and runs tasks sequentially.
        Ensures each task is completely finished before launching another.
        """
        print("Smart mode: Changing MAC addresses, running tasks with random delays, and running tasks sequentially.")
    
        self.PrivateScanner.GetNetworkData(PrintDetails=False)
        for i, task in enumerate(self.tasks):
            try:
                self.PrivateScanner.change_mac(RandomMAC=True)
                time.sleep(delay)
                print(f"Starting task {i + 1}/{len(self.tasks)}")
                task.start()
                task.join()  # Ensure the task is finished
                print(f"Task {i + 1} completed")
    
            except Exception as e:
                print(f"[!] Error in task {i + 1}: {e}")
            finally:
                if task.is_alive():
                    try:
                        task.terminate()
                        task.join()  # Ensure termination is complete
                        print(f"Task {i + 1} was forcefully terminated")
                    except Exception as e:
                        print(f"[!] Error terminating task {i + 1}: {e}")
    
            time.sleep(delay)
    
        try:
            self.PrivateScanner.change_mac(Reverse_Mode=True)
        except Exception as e:
            print(f"[!] Error reverting MAC address: {e}")
        time.sleep(delay)

        
        
    
    
    
    
    




if __name__ == "__main__":
    pass