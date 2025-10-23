import threading
import time
# import sys  # Not needed if modules are in same repo

import employeemonitor1 as module1
import sensitivefile as module2

def run_module1():
    print("▶ Starting Module 1 (Employee Behavior + Gmail Monitor)...")
    module1.monitor_employee("Employee1")  # Placeholder employee name for public upload

def run_module2():
    print("▶ Starting Module 2 (Sensitive File + Warnings System)...")
    current_user = "Employee1"  # Placeholder username
    module2.monitor_employee(current_user)

if __name__ == "__main__":
    # Run both modules independently in separate threads
    t1 = threading.Thread(target=run_module1)
    t2 = threading.Thread(target=run_module2)

    t1.start()
    time.sleep(2)  # small delay to prevent webcam conflicts
    t2.start()

    # Wait for both to finish
    t1.join()
    t2.join()

    print("✅ Monitoring completed.")



