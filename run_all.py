#!/usr/bin/env python
# encoding: utf-8

import sys
import collections
import datetime
from time import time
from multiprocessing import Pool
from subprocess import call
from itertools import product

# configure here
num_runs = 1  # number of runs per configuration (each with a different seed)
num_workers = 1  # number of parallel runs
start_seed = 1

_parameter_lists = [[('MonitorApp::ObservationPeriod="1s"', 'RouterApp::ObservationPeriod="1s"'),
                     ('MonitorApp::ObservationPeriod="2s"', 'RouterApp::ObservationPeriod="2s"'),
                     ('MonitorApp::ObservationPeriod="5s"', 'RouterApp::ObservationPeriod="5s"'),
                     ('MonitorApp::ObservationPeriod="10s"', 'RouterApp::ObservationPeriod="10s"'),
                     ('MonitorApp::ObservationPeriod="20s"', 'RouterApp::ObservationPeriod="20s"'),


                     ('ns3::ndn::fw::MonitorAwareRouting::tau="0.1"'),
                     ('ns3::ndn::fw::MonitorAwareRouting::tau="0.2"'),
                     ('ns3::ndn::fw::MonitorAwareRouting::tau="0.3"'),
                     ('ns3::ndn::fw::MonitorAwareRouting::tau="0.5"'),
                     ('ns3::ndn::fw::MonitorAwareRouting::tau="0.7"'),

                     ('gamma="0.1"'),
                     ('gamma="0.2"'),
                     ('gamma="0.3"'),
                     ('gamma="0.5"'),
                     ('gamma="0.7"'),

                     ('PITLifetime="0.5s"'),
                     ('PITLifetime="1s"'),
                     ('PITLifetime="2s"'),
                     ('PITLifetime="5s"'),
                     ('PITLifetime="10s"'),

                     ('PITSize="1000"'),
                     ('PITSize="2000"'),
                     ('PITSize="5000"'),
                     ('PITSize="10000"'),
                     ('PITSize="20000"'),

                     ('CacheSize="0"'),
                     ('CacheSize="100"'),
                     ('CacheSize="500"'),
                     ('CacheSize="1000"'),
                     ('CacheSize="5000"'),

                     ('ns3::ndn::CnmrClient::Frequency="10"'),
                     ('ns3::ndn::CnmrClient::Frequency="50"'),
                     ('ns3::ndn::CnmrClient::Frequency="100"'),
                     ('ns3::ndn::CnmrClient::Frequency="500"'),
                     ('ns3::ndn::CnmrClient::Frequency="1000"'),

                     ('ns3::ndn::CnmrServer::PayloadSize="100"'),
                     ('ns3::ndn::CnmrServer::PayloadSize="500"'),
                     ('ns3::ndn::CnmrServer::PayloadSize="1100"'),
                     ('ns3::ndn::CnmrServer::PayloadSize="3000"'),

                     ('ns3::ndn::CnmrFloodingAttacker::Frequency="1000"'),
                     ('ns3::ndn::CnmrFloodingAttacker::Frequency="2000"'),
                     ('ns3::ndn::CnmrFloodingAttacker::Frequency="5000"'),
                     ('ns3::ndn::CnmrFloodingAttacker::Frequency="10000"'),
                     ('ns3::ndn::CnmrFloodingAttacker::Frequency="20000"'),

                     ]]

_topology_list = [('TopologyFile="topologies/AS-3967_delays.ns3.txt"', 'MonitorRouters="19,39,58,9,51,59,54,48"', 'EgressRouters="61,62,63"', 'IngressRouters="{}"'.format(','.join(map(str, range(56))))),
                  # ('TopologyFile="topologies/xw1239.txt"', 'MonitorRouters="96,164,65,219,95,64,218,34,198,93,294,196,197,53,62,275,167,273,161,35,202,253,150,260,107,225,156,97,63,165,134,152"', 'EgressRouters="221,222,223"', 'IngressRouters="{}"'.format(','.join(map(str, range(220))))),
                  # ('TopologyFile="topologies/xw1755.txt"', 'MonitorRouters="0,26,33,50,56,7,27,67,8"', 'EgressRouters="61,62,63"', 'IngressRouters="{}"'.format(','.join(map(str, range(60))))),
                  # ('TopologyFile="topologies/xw3257.txt"', 'MonitorRouters="69,59,101,99,57,48,88,27,102,47,71,103,125,2,100,61,64"', 'EgressRouters="114,115,116"', 'IngressRouters="{}"'.format(','.join(map(str, range(112))))),
                  ]

_seed_template = 'RngSeed="{}"'
_seeds = [_seed_template.format(n) for n in range(start_seed, start_seed + num_runs)]


def flatten(l):
    for el in l:
        if isinstance(el, collections.Iterable) and not isinstance(el, str):
            for x in el:
                yield x
        else:
            yield el

finished_runs = 0


def run(parameter):
    global finished_runs
    num_simulations = len(list(product(_seeds, _topology_list, *_parameter_lists)))
    finished_runs += 1

    start = int(time())
    ret = call(['python2', './waf', '--run=ndn-cnmr {}'.format(parameter)])
    end = int(time())
    print("Run {}/{} {} {} [{}]".format(finished_runs, num_simulations, 'finished in' if ret == 0 else 'failed after', str(datetime.timedelta(seconds=end - start)), parameter))


def main():
    pool = Pool(processes=num_workers)

    arguments = set()

    # for configuration in list(product(_seeds, *_tree_parameter_list)) + list(product(_seeds, *_as_parameter_list)):
    for configuration in list(product(_seeds, _topology_list, *_parameter_lists)):
        run_configuration = list(flatten(configuration))
        str_configuration = '--' + ' --'.join(run_configuration)
        print(str_configuration)
        arguments.add(str_configuration)

    start = int(time())
    print("Starting {} runs.".format(len(arguments)))
    if not (len(sys.argv) > 1 and sys.argv[1] == '-n'):
        try:
            pool.map(run, arguments)
        except KeyboardInterrupt:
            pool.terminate()
            pass
    end = int(time())
    print("Completed all runs in {}".format(str(datetime.timedelta(seconds=end - start))))

if __name__ == '__main__':
    main()
