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
            processes[task.UniqueProcessId] = {}
            processes[task.UniqueProcessId]["name"] = task.ImageFileName
            processes[task.UniqueProcessId]["ppid"] = task.InheritedFromUniqueProcessId
            process_params = task.Peb.ProcessParameters
            if process_params:
                processes[task.UniqueProcessId]["cmdline"] = process_params.CommandLine
            else:
                processes[task.UniqueProcessId]["cmdline"] = "N/A"

        return processes

    def render_text(self, outfd, data):
        outfd.write("PID\tPPID\tNAME\n")
        for ps in data:
            outfd.write("{0}\t{1}\t{2}\n".format(ps,
                                                data[ps]["ppid"],
                                                data[ps]["name"]
                                                )
                )
