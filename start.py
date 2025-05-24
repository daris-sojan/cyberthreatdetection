import subprocess
import sys
import time
import os

def start_system():
    print("🚀 Starting Cyber Threat Monitor System...")
    
    # Start the log generator in a separate process
    log_gen_process = subprocess.Popen([sys.executable, "log_generator.py"])
    
    # Give the log generator a moment to start
    time.sleep(2)
    
    # Start the main system
    main_process = subprocess.Popen([sys.executable, "run.py"])
    
    try:
        # Keep the script running and monitor the processes
        while True:
            if main_process.poll() is not None:
                print("❌ Main system stopped unexpectedly")
                break
            if log_gen_process.poll() is not None:
                print("❌ Log generator stopped unexpectedly")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down system...")
    finally:
        # Cleanup processes
        log_gen_process.terminate()
        main_process.terminate()
        print("✅ System shutdown complete")

if __name__ == "__main__":
    start_system() 