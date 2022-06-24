# Author: Jose Luis Sanchez Martinez - @Joseliyo_Jstnk
# Version: 0.0.1
# GitHub: https://github.com/jstnk9
import time, json, etw, psutil, argparse, os
from treelib import Node, Tree
from treelib import exceptions

def main(args):
    providers = [etw.ProviderInfo('Microsoft-Windows-Kernel-Process', etw.GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"))]
    whitelist = set()
    tree = Tree()
    tree.create_node("ETW-Almulahaza", "ETW-Almulahaza")

    if args.pid_list:
        whitelist = set(args.pid_list)
        
    if args.add_explorer:
        for proc in psutil.process_iter():
            try:
                if proc.name() == "explorer.exe":
                    whitelist.add(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                print("[*] Explorer.exe couldn't be added to the process monitoring.")
                pass

    job = etw.ETW(providers=providers, pid_whitelist=whitelist, task_name_filters=["PROCESSSTART", "PROCESSSTOP", "THREADSTART", "THREADSTOP"], session_name="ETW-Session-PythonController", event_callback=lambda x: consumer(x, job, tree))
    job.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("[*] Session stopped")
        job.stop()

def consumer(x, job, tree):
    jsonObj = json.dumps(x)
    jsonArr = json.loads(jsonObj)

    with open("raw-traces.json", "a") as f:

        if jsonArr[1]["Task Name"] == "PROCESSSTART":
            json.dump(jsonArr[1], f)
            job.add_pid_whitelist(int(jsonArr[1]["ProcessID"]))

            try:
                tree.create_node("Process Name: %s (%s)"%(jsonArr[1]["ImageName"].split("\\")[-1], jsonArr[1]["ProcessID"]), jsonArr[1]["ProcessID"], parent="%s"%(jsonArr[1]["ParentProcessID"]))
            except exceptions.NodeIDAbsentError as e:
                tree.create_node("Process Name: %s (%s)"%(jsonArr[1]["ImageName"].split("\\")[-1], jsonArr[1]["ProcessID"]), jsonArr[1]["ProcessID"], parent="ETW-Almulahaza")

        if jsonArr[1]["Task Name"] == "PROCESSSTOP":
            json.dump(jsonArr[1], f)
            job.remove_pid_whitelist(int(jsonArr[1]["ProcessID"]))
            tree.update_node(jsonArr[1]["ProcessID"], tag="Process Name: %s (%s) - stopped"%(jsonArr[1]["ImageName"].split("\\")[-1], jsonArr[1]["ProcessID"]))

        if jsonArr[1]["Task Name"] == "THREADSTART":
            json.dump(jsonArr[1], f)
            tree.create_node("ThreadID: %s"%(jsonArr[1]["ThreadID"]), jsonArr[1]["ThreadID"], parent="%s"%(jsonArr[1]["ProcessID"]))

        if jsonArr[1]["Task Name"] == "THREADSTOP":
            json.dump(jsonArr[1], f)
            tree.update_node(jsonArr[1]["ThreadID"], tag="ThreadID: %s - stopped"%(jsonArr[1]["ThreadID"]))
    
    os.system("cls")
    tree.show(key=False)

       
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ETW-Almulahaza is a consumer python-based tool that help you monitor ETW events of the operating system. All the raw traces are stored in the path where it was executed with the name raw-traces-json")
    parser.add_argument("--add-explorer", dest="add_explorer", required=False, action="store_true", help="Use this parameter if you want to monitor explorer.exe and its childrens.")
    parser.add_argument("--add-pid", nargs="+", dest="pid_list", required=False, type=int, help="Use this parameter to set the PID or PIDs that you want to monitor. Example: python.py ETW-Almulahaza --add-pid 149, 2241, 499")
    args = parser.parse_args() 

    if not args.add_explorer and not args.pid_list:
        parser.error("One of --add-explorer or --add-pid must be given")
    else:
        main(args)
