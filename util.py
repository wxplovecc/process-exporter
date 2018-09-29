import psutil
import sys

def get_process(pid):
    p = psutil.Process(pid=pid)
    with p.oneshot():
        print p.name(),p.cpu_times(),p.cpu_percent(),p.ppid(),p.status(),p.memory_percent(),p.memory_info()


def find_procs_by_name(name):
    "Return a list of processes matching 'name'."
    ls = []
    for p in psutil.process_iter(attrs=["name"]):
        if name == p.info['name']:
            p_info = p.as_dict(attrs=["pid","name", "cpu_percent", "memory_percent", "username", "num_threads", "num_fds"])
            num_ctx_switches = p.num_ctx_switches()
            pio =p.io_counters()
            p_info["num_ctx_switches_voluntary"] = num_ctx_switches.voluntary
            p_info["num_ctx_switches_involuntary"] = num_ctx_switches.involuntary
            p_info["pio_write_count"] = pio.write_count
            p_info["pio_read_count"] = pio.read_count
            p_info["pio_write_bytes"] = pio.write_bytes
            p_info["pio_read_bytes"] = pio.read_bytes
            p_info["pio_write_chars"] = pio.write_chars
            p_info["pio_read_chars"] = pio.read_chars
            p_info["exec"] = '-'.join(p.cmdline()[-2:])
            ls.append(p_info)
    return ls


if __name__ =="__main__":
    process_name = sys.argv[1]
    result = find_procs_by_name(name=process_name)
    for i in result:
        for j in i:
            if j in ["pid", "name", "exec"]:
                continue
            print ("%s {pid=\"%s\",name=\"%s\",exec=\"%s\"} %s" % (j, i["pid"], i["name"], i["exec"], i[j]))