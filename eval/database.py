#!/usr/bin/env python2
# encoding: utf-8

import logging
import re
import sys
from os import listdir, path, chdir, getcwd
import dataset

match_filename = \
    re.compile("topo=(?P<topo>.*)_mar=(?P<mar>\d)_ftbm=(?P<ftbm>\d)_detection=(?P<detection>\d)_numServers=(?P<numServers>\d*)"
               "_payloadSize=(?P<payloadSize>\d*)_numClients=(?P<numClients>\d*)@(?P<clientFrequency>\d*)"
               "_numAttackers=(?P<numAttackers>\d*)@(?P<attackersFrequency>\d*)_numMonitors=(?P<numMonitors>\d*)"
               "_tau=(?P<tau>.*)_observationPeriod=(?P<observationPeriod>\d*)s_gamma=(?P<gamma>.*)_cacheSize=(?P<cacheSize>\d*)"
               "_pitSize=(?P<pitSize>\d*)_pitLifetime=(?P<pitLifetime>.*)s_run=(?P<run>\d*)_seed=(?P<seed>\d*)-(.*)")

_filename_template = \
    "topo={topo}_mar={mar}_ftbm={ftbm}_detection={detection}_numServers={numServers}" \
    "_payloadSize={payloadSize}_numClients={numClients}@{clientFrequency}" \
    "_numAttackers={numAttackers}@{attackersFrequency}_numMonitors={numMonitors}" \
    "_tau={tau}_observationPeriod={observationPeriod}s_gamma={gamma}_cacheSize={cacheSize}" \
    "_pitSize={pitSize}_pitLifetime={pitLifetime}s_run={run}_seed={seed}-{logFile}.txt"


def make_filename(run, log_file):
    return _filename_template.format(**dict(run.items() + {'logFile':
                                                           log_file}.items()))


def get_runs():
    runs = []
    checked_files = set()
    for filename in listdir('.'):
        if not filename.endswith('.txt') or filename in checked_files:
            continue

        run = eval_filename(filename)
        has_all_log_files = True

        for log_file in ('cc', 'l3trace', 'pit'):
            # Check if all 4 log files exist
            log_file_name = make_filename(run, log_file)
            checked_files.add(log_file_name)
            if not path.isfile(log_file_name):
                has_all_log_files = False
                break

        if run not in runs and has_all_log_files:
            runs.append(run)

    return runs


def eval_filename(name):
    matched = match_filename.search(name)
    if matched:
        groupdict = matched.groupdict()

        # Convert some to int
        for column in ('mar', 'ftbm', 'detection', 'numServers', 'numClients',
                       'numAttackers', 'attackersFrequency', 'numMonitors',
                       'cacheSize', 'run', 'seed', 'observationPeriod',
                       'clientFrequency', 'payloadSize',
                       'pitSize'):
            groupdict[column] = int(groupdict[column])

        if groupdict['pitLifetime'].count('.') > 0:
            groupdict['pitLifetime'] = float(groupdict['pitLifetime'])
        else:
            groupdict['pitLifetime'] = int(groupdict['pitLifetime'])

        # Convert some to float
        for column in ('tau', 'gamma'):
            # make sure 0 is represented as 0 and not as 0.0
            if groupdict[column] == '0':
                groupdict[column] = 0
            else:
                groupdict[column] = float(groupdict[column])

        return groupdict


def read_run(run, db):
    experiment_table = db['experiments']
    experiment_id = experiment_table.insert(run)

    read_log_file(run, experiment_id, db, 'l3trace', eval_l3trace_line)
    read_log_file(run, experiment_id, db, 'pit', eval_pit_line)
    read_log_file(run, experiment_id, db, 'cc', eval_cc_line)


def eval_l3trace_line(line):
    """ Example file:
        =============
            Time	Node	FaceId	FaceDescr	Type	Packets	Kilobytes
            10	client0	0	dev[15]=net(0,15-0)	InInterests	0	0
            10	client0	0	dev[15]=net(0,15-0)	OutInterests	992	35.5723
            10	client0	0	dev[15]=net(0,15-0)	DropInterests	0	0
            10	client0	0	dev[15]=net(0,15-0)	InData	801	832.854
            10	client0	0	dev[15]=net(0,15-0)	OutData	0	0
            10	client0	0	dev[15]=net(0,15-0)	DropData	0	0
            10	client0	2	dev=local(2)	InInterests	992	0
            10	client0	2	dev=local(2)	OutInterests	0	0
            10	client0	2	dev=local(2)	DropInterests	0	0
            10	client0	2	dev=local(2)	InData	0	0
            10	client0	2	dev=local(2)	OutData	801	832.854
            10	client0	2	dev=local(2)	DropData	0	0
            10	client0	-1	all	SatisfiedInterests	801	0
            10	client0	-1	all	TimedOutInterests	0	0
    """
    time, node, faceId, faceDescr, signal, packets, kilobytes = line.split()
    parsed = dict(time=float(time), node=node, faceId=faceId, faceDescr=faceDescr,
                  signal=signal, packets=int(packets), kilobytes=float(kilobytes))
    return parsed


def eval_pit_line(line):
    """ Example file:
        =============
            Time	Node	Signal	Value
            10	monitor0	PitUsage	0.096
            10	monitor1	PitUsage	0.093
    """
    time, node, signal, value = line.split()
    return dict(time=float(time), node=node, signal=signal, value=float(value))


def eval_cc_line(line):
    """ Example file:
        =============
            Time	Node	Face	Signal	Value
            10	CC	all	GlobalUsage	0.0943472
            10	CC	all	AvgLocalUsage	0.0943472
            10	CC	all	GlobalSatisfaction	0.799776
            10	CC	all	AvgLocalSatisfaction	0.802287
            10	CC	all	Overhead	2304
    """
    time, node, face, signal, value = line.split()
    return dict(time=float(time), node=node, face=face, signal=signal,
                value=float(value))


def read_log_file(run, experiment_id, db, column, eval_line_function):
    log_file_name = make_filename(run, column)
    logging.debug('Reading file {}'.format(log_file_name))

    measurement_table = db[column]

    with open(log_file_name, 'r') as f:
        for line in f.readlines():
            if line:  # skip the header
                try:
                    measurement = eval_line_function(line.strip())
                    if(measurement):
                        measurement['experiment_id'] = experiment_id
                        measurement_table.insert(measurement)
                except ValueError:
                    if not line.startswith('Time'):  # skip header line
                        logging.warn('Could not parse line: "{}" in file '
                                     '{}'.format(line.strip(), log_file_name))


def read(directory):
    db = dataset.connect('sqlite:///:memory:')
    old_path = getcwd()
    chdir(directory)

    runs = get_runs()

    if(len(runs) == 0):
        logging.error("Could not find any runs. Exiting.")
        sys.exit(1)
    else:
        logging.info('Found ' + str(len(runs)) + ' runs.')

    logging.info('Reading run files...')
    num_files = len(runs) * 3
    for i, run in enumerate(runs, start=1):
        read_run(run, db)
        logging.info("Read {}/{} files.".format(i * 3, num_files))

    chdir(old_path)

    logging.info('Read ' + str(len(db['l3trace']) + len(db['pit']) +
                               len(db['cc'])) + ' measurements.')
    return db


def main():
    if(len(sys.argv) > 1 and sys.argv[1]):
        read(sys.argv[1])
        raw_input("Press any key to terminate database...")
    else:
        logging.error("Please define a directory with log files to read.")
        sys.exit()

if __name__ == '__main__':
    main()
