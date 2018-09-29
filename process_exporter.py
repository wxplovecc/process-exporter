import psutil
import logging
import argparse
import time
import sys
import re
import os
import socket
import yaml
from threading import Thread

from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY

logging.basicConfig(
    level=logging.INFO,
    format=
    '%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
    datefmt='%a, %d %b %Y %H:%M:%S')
logging = logging.getLogger(sys.path[0] + 'process_exporter')


def quit_script(msg, exit_code):
    print msg
    sys.exit(exit_code)


class CollectThread(Thread):
    def __init__(self, id, pid, metric):
        Thread.__init__(self)
        self.id = id
        self.name = id + "test"
        self.pid = pid
        self.metric = metric

    def run(self):
        self.get_process_metrics()

    def get_process_metrics(self):
        '''
        This function is setup to scrape process metrics, such as CPU, Mem, uptime, status and so on.
        All the metrics can be scraped in the /proc/pid/stat file. However, here I uesed a third-party liberary "psutil"
        to get all data I need.
        @pid: PID get by get_pid() function.
        @return: return a dict of all metrics I need.
        '''
        process_metrics = {}
        try:
            process = psutil.Process(int(self.pid))
            cmdline = process.cmdline()
            process_metrics = {
                "create_time": process.create_time(),
                # "io_counters": process.io_counters()._asdict(),
                "cpu_times": process.cpu_times()._asdict(),
                "memory_percent": process.memory_percent(),
                "memory_info": process.memory_info()._asdict(),
                # "num_fds": process.num_fds()
                "num_threads": process.num_threads(),
                "cwd": process.cwd(),
                "cmdline": cmdline[-1],
                "exe": process.exe(),
                "cpu_percent": process.cpu_percent(interval=1),
                "pid": str(process.pid)
                # "open_files": len(process.open_files())
            }
        except Exception, err:
            logging.error("No pid {0} found, please check ! ".format(err))
            print 1, err
            pass
        self.metric[self.id] = process_metrics


class ProcessCollector(object):
    def __init__(self, config_file):
        try:
            with open(os.path.expanduser(config_file), 'r') as cf:
                self.config = yaml.load(cf)
        except Exception as e:
            quit_script(str(e), 1)

    def collect(self):
        try:
            hostname = socket.gethostname()
            # allCpu
            allCpu = GaugeMetricFamily(
                'offline_machine_cpu_percentage',
                'machine cpu percentage',
                labels=['host'])
            allCpu.add_metric([hostname], value=psutil.cpu_percent())
            yield allCpu

            # all mem
            allMem = GaugeMetricFamily(
                'offline_machine_mem_percentage',
                'machine mem percentage',
                labels=['host'])
            allMem.add_metric([hostname],
                              value=psutil.virtual_memory().percent)
            yield allMem

            # all disk
            allDisk = GaugeMetricFamily(
                'offline_machine_disk_percentage',
                'machine disk percentage',
                labels=['host'])
            allDisk.add_metric([hostname],
                               value=psutil.disk_usage('/').percent)
            yield allDisk

            process_names = self.config['check_processes']
            for process_name in process_names:
                print 'process_name = %s ' % (process_name)

                allProcess = get_pid(process_name)

                metrics = {}

                ThreadList = []
                for i, value in enumerate(allProcess):
                    t = CollectThread(str(i), value['pid'], metrics)
                    ThreadList.append(t)
                for t in ThreadList:
                    t.start()
                for t in ThreadList:
                    t.join()

                for key, process_metrics in metrics.iteritems():

                    snake_case = process_name.lower()
                    process_count = GaugeMetricFamily(
                        'offline_process_count',
                        snake_case + ' Total Running time in seconds.',
                        labels=['pid', 'exe', 'cmd', 'host'])
                    process_count.add_metric([
                        process_metrics['pid'], process_name,
                        process_metrics['cmdline'], hostname
                    ],
                                             value=1)
                    yield process_count

                    if process_metrics:
                        runningTime = GaugeMetricFamily(
                            'offline_process_running_time_seconds_total',
                            snake_case + ' Total Running time in seconds.',
                            labels=['pid', 'exe', 'cmd', 'host'])
                        runningTime.add_metric(
                            [
                                process_metrics['pid'], process_name,
                                process_metrics['cmdline'], hostname
                            ],
                            value=process_metrics['create_time'])
                        yield runningTime
                        # cpu
                        cpu = GaugeMetricFamily(
                            'offline_process_cpu_percentage',
                            snake_case + ' CPU Percentage.',
                            labels=['pid', 'exe', 'cmd', 'host'])
                        cpu.add_metric([
                            process_metrics['pid'], process_name,
                            process_metrics['cmdline'], hostname
                        ],
                                       value=process_metrics['cpu_percent'])
                        yield cpu

                        # mempersent
                        mempersent = GaugeMetricFamily(
                            'offline_process_mem_percentage',
                            snake_case + ' mem Percentage.',
                            labels=['pid', 'exe', 'cmd', 'host'])
                        mempersent.add_metric(
                            [
                                process_metrics['pid'], process_name,
                                process_metrics['cmdline'], hostname
                            ],
                            value=process_metrics['memory_percent'])
                        yield mempersent

                        threadCount = GaugeMetricFamily(
                            'offline_process_threads_number',
                            snake_case + ' Total Number of Threads.',
                            labels=['pid', 'exe', 'cmd', 'host'])
                        threadCount.add_metric(
                            [
                                process_metrics['pid'], process_name,
                                process_metrics['cmdline'], hostname
                            ],
                            value=process_metrics['num_threads'])

                        yield threadCount

                    else:
                        pass
        except Exception, err:
            print 1, err
        finally:
            pass


def get_pid(process_name):
    list = []
    for p in psutil.process_iter(attrs=['pid', 'name']):
        try:
            p.exe()
        except Exception, err:
            # print 1, err
            pass
        else:
            a = p.exe().split('\\')
            # print a -1
            if process_name in a[-1]:
                list.append(p.info)
    return list
    # return [
    #     p.info
    #     for p in psutil.process_iter(attrs=['pid', 'name', 'cmdline', 'exe'])
    #     if process_name in p['exe']
    # ]


def main():
    try:
        args = parse_args()
        port = int(args.port)
        REGISTRY.register(ProcessCollector(args.config))
        start_http_server(port)
        print "Polling %s. Serving at port: %s" % (args.address, port)
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print "Interrupted"
        sys.exit(0)


def parse_args():
    parser = argparse.ArgumentParser(
        description='process status exporter args, including address and port')
    parser.add_argument(
        '--telemetry-path',
        metavar='telemetry_path',
        required=False,
        help='Path under which to expose metrics. (default "/metrics")',
        default='/metrics')
    parser.add_argument(
        '--address',
        metavar='address',
        required=False,
        help='Running on this address. (default "127.0.0.1")',
        default='127.0.0.1')
    parser.add_argument(
        '--config',
        metavar='config',
        required=False,
        help='config check list. (default "java")',
        default=['java'])
    parser.add_argument(
        '-p',
        '--port',
        metavar='port',
        required=False,
        type=int,
        help='Listen to this port. (default ":9108")',
        default=int(os.environ.get('VIRTUAL_PORT', '9108')))
    return parser.parse_args()


if __name__ == "__main__":
    main()
