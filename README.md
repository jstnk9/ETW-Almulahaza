# ETW-Almulahaza

ETW-Almulahaza is a consumer python-based tool that help you monitor ETW events of the operating system. The purpose of this tool is to help analysts during researching of either malware or simply lolbas or other binaries that are intended to understand their behavior. 

This project uses [pywintrace](https://github.com/fireeye/pywintrace) lib.

# Installation

Python3 is needed to run this script. Also is needed execute the script with admin privileges.

First of all **you must** install [pywintrace](https://github.com/fireeye/pywintrace) using the file `setup.py` and not thru pip. After download pywintrace, run the following command.

```
python setup.py install
```

Once it is executed, install the dependencies used by the tool by cloning this repository and executing the following command.

```
pip install -r requirements.txt
```

# Usage

After installing all the dependencies, the use of the script is simple.

```
> python .\etw-almulahaza.py -h
usage: etw-almulahaza.py [-h] [--add-explorer] [--add-pid PID_LIST [PID_LIST ...]]

ETW-Almulahaza is a consumer python-based tool that help you monitor ETW events of the operating system. All the raw traces are stored in the path where it was executed with the name raw-traces-json

options:
  -h, --help            show this help message and exit
  --add-explorer        Use this parameter if you want to monitor explorer.exe and its childrens.
  --add-pid PID_LIST [PID_LIST ...]
                        Use this parameter to set the PID or PIDs that you want to monitor. Example: python.py ETW-
                        Almulahaza --add-pid 149, 2241, 499
```

All the traces generated are stored in a file called `raw-traces.json`.

## Examples

Monitor the processID 14944 and its childrens

```
>  python .\etw-almulahaza.py --add-pid 14944
```

When the processID 14944 starts a new process, it is added on the fly into the whitelist to monitor. Also, you can see a process tree in your terminal with the information about the processes and threads.

![processtree](https://github.com/jstnk9/ETW-Almulahaza/blob/main/img/process-tree.jpg?raw=true) 


Monitor `explorer.exe` and its childrens.

```
>  python .\etw-almulahaza.py --add-explorer
```

# ToDo 
[] Add config file to specify providers to monitor and task names
[] Convert outputs in other formats
[] Add providers on the fly
[] ....
