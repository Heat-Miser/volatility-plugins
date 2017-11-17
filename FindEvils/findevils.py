import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.plugins.common as common


class FindEvils(common.AbstractWindowsCommand):
    """Implements the checks described in the Find Evils SANS poster"""

    def calculate(self):
        processes = {}
        addr_space = utils.load_as(self._config)
        mytasks = tasks.pslist(addr_space)
        
        for task in mytasks:
            pid =  "{0}".format(task.UniqueProcessId)
            name =  "{0}".format(task.ImageFileName)
            ppid = "{0}".format(task.InheritedFromUniqueProcessId)
            createtime = "{0}".format(task.CreateTime)
            sessionid =  "{0}".format(task.SessionId)
            cmdline = ""
            process_params = task.Peb.ProcessParameters
            if process_params:
                cmdline = "{0}".format(process_params.CommandLine)
            else:
                cmdline = "NA"
            
            if name not in processes:
                processes[name] = []
            
            newpp = {}
            newpp["pid"] = pid
            newpp["name"] = name
            newpp["ppid"] = ppid
            newpp["cmdline"] = cmdline
            newpp["sessionid"] = sessionid
            processes[name].append(newpp)

        return processes

    def render_text(self, outfd, data):
        process_system = None 
        first_smss = None


        processname = "System"
        outfd.write("\n##### Checking %s process #####\n" % (processname))
        if processname in data:
            outfd.write("OK: %s process exists\n" % (processname))
            if len(data[processname]) == 1:
                outfd.write("OK: %s process only seen one time\n" % (processname))
                if data[processname][0]["ppid"] == "0":
                    process_system = data[processname][0]
                    outfd.write("OK: %s process has no parent\n" % (processname))
                else:
                    outfd.write("KO: %s process has %s process has parent\n" % (processname, data[processname][0]["ppid"]))
            else:
                outfd.write("KO: %s System is present %s times\n" % (processname, len(data[processname])))
        else:
            outfd.write("OK: %s process doen't exist\n" % (processname))
        
        processname = "smss.exe"
        outfd.write("\n##### Checking %s process #####\n" % (processname))

        # Identifiying first smss.exe process
        for process in data[processname]:
            if process["ppid"] == process_system["pid"]:
                first_smss = process

        if processname in data:
            outfd.write("OK: %s process exists\n" % (processname))
            if len(data[processname]) == 1:
                outfd.write("OK: %s process exists only one time\n" % (processname))
            else:
                for smss in data[processname]:
                    if smss == first_smss or smss["ppid"] == first_smss["pid"]:
                        continue
                    else:
                        outfd.write("KO: %s (%s) process is not a child of original %s process\n" % (processname, smss["pid"], processname))
                outfd.write("OK: all the %s processes are related to System or original %s\n" % (processname, processname))
        else:
            outfd.write("OK: %s process doen't exist\n" % (processname))

        # for process in data:
            # outfd.write("%s: seen %s times\n" % (process, len(data[process])))

