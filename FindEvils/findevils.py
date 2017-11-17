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
            newpp["ppid"] = ppid
            newpp["cmdline"] = cmdline
            processes[name].append(newpp)

        return processes

    def render_text(self, outfd, data):
        for process in data:
            outfd.write("%s: seen %s times\n" % (process, len(data[process])))

