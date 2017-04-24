#!/usr/bin/env python2
# encoding: utf-8

from __future__ import division
from collections import defaultdict
from os import path
import inspect
import cPickle as pickle
import logging
import sys

from database import read
from plot import plot_over_time, make_sure_path_exists

PICKLE_DIR = './eval/pickle/'


def pickleable(processor, *args, **kw):
    def decorated(*args, **kw):
        # Get the line number from where this has been called. That way I can
        # pickle each call to a seperate file a restore the data
        lineno = inspect.currentframe().f_back.f_lineno

        identifier = '_'.join([processor.func_name, str(lineno)])
        pickle_file = path.join(PICKLE_DIR, identifier)

        if type(args[0]) is not DummyDB:
            result = processor(*args, **kw)
            pickle.dump(result, open(pickle_file, "wb"))
            return result
        elif path.isfile(pickle_file):
            return pickle.load(open(pickle_file, "rb"))
        else:
            logging.error('Cannot find pickled data nor database. Specify an output directory')
            sys.exit(1)
    return decorated


@pickleable
def get_cc_metric_over_time(db, experiments, signal, legend):
    data = []
    for experiment in experiments:

        if experiment['detection'] not in (3, ):
            # CC metrics are only relevant when CC help is actually used
            continue

        current_experiment = defaultdict(list)

        # Iterate over all seeds of that experiment
        for run in db['experiments'].find(**experiment):
            for m in db['cc'].find(experiment_id=run['id'], signal=signal):
                current_experiment[m['time']].append(m['value'])

        times = []
        values = []
        for time in sorted(current_experiment.keys()):
            times.append(time)
            values.append(sum(current_experiment[time]) /
                          len(current_experiment[time]))

        label = ', '.join('{}={}'.format(l, run[l]) for l in legend)

        data.append((times, values, label))
    return data


@pickleable
def get_real_satisfaction_ratio(db, experiments, legend, nodes=""):
    data = []
    for experiment in experiments:
        sat_ratio_over_time = dict()

        # Iterate over all seeds of that experiment
        for run in db['experiments'].find(**experiment):
            satisfied = defaultdict(list)
            timedOut = defaultdict(list)

            for m in db['l3trace'].find(experiment_id=run['id'], faceDescr='all', signal='SatisfiedInterests'):
                if not m['node'].startswith('server') and not m['node'].startswith('monitor'):
                    if m['node'].startswith(nodes):
                        satisfied[m['time']].append(m['packets'])

            for m in db['l3trace'].find(experiment_id=run['id'], faceDescr='all', signal='TimedOutInterests'):
                if not m['node'].startswith('server') and not m['node'].startswith('monitor'):
                    if m['node'].startswith(nodes):
                        timedOut[m['time']].append(m['packets'])

        for time in sorted(satisfied.keys()):
            total_satisfied = sum(satisfied[time])
            total_timedOut = sum(timedOut[time])
            if total_timedOut == 0:
                sat_ratio_over_time[time] = 1
            else:
                sat_ratio_over_time[
                    time] = total_satisfied / (total_satisfied + total_timedOut)

        times = []
        values = []
        for time in sorted(sat_ratio_over_time.keys()):
            times.append(time)
            values.append(sat_ratio_over_time[time])
        label = ', '.join('{}={}'.format(l, experiment[l]) for l in legend)
        data.append((times, values, label))
    return data


@pickleable
def get_overhead_size(db, experiments, legend, sent=True, received=True):
    data = []
    for experiment in experiments:
        if experiment['detection'] not in (3, ):
            # Only calculate overhead when CC help is actually used
            continue

        overhead = defaultdict(list)
        traffic = defaultdict(list)

        # Iterate over all seeds of that experiment
        for run in db['experiments'].find(**experiment):
            if sent:
                # Include overhead resulting from sent messages
                for m in db['cc'].find(experiment_id=run['id'], signal="SizeSent"):
                    overhead[m['time']].append(m['value'] / 1000)  # byte to kilobyte

            if received:
                # Include overhead resulting from received messages
                for m in db['cc'].find(experiment_id=run['id'], signal="SizeReceived"):
                    overhead[m['time']].append(m['value'] / 1000)  # byte to kilobyte

            for m in db['l3trace'].find(experiment_id=run['id'], signal="OutData"):
                if(m['faceDescr'].count('net') and  # skip local interfaces (faces to apps)
                   m['node'].startswith('server')):
                    traffic[m['time']].append(m['kilobytes'])

        times = []
        values = []
        for time in sorted(overhead.keys()):
            times.append(time)
            try:
                values.append(sum(overhead[time]) / sum(traffic[time]))
            except ZeroDivisionError:
                values.append(0)

        label = ', '.join('{}={}'.format(l, run[l]) for l in legend)

        data.append((times, values, label))
    return data


@pickleable
def get_overhead_msgs(db, experiments, legend, sent=True, received=True):
    data = []
    for experiment in experiments:
        if experiment['detection'] not in (3, ):
            # Only calculate overhead when CC help is actually used
            continue

        overhead = defaultdict(list)

        # Iterate over all seeds of that experiment
        for run in db['experiments'].find(**experiment):
            if sent:
                # Include overhead resulting from sent messages
                for m in db['cc'].find(experiment_id=run['id'], signal="NumSent"):
                    overhead[m['time']].append(m['value'])  # byte to kilobyte

            if received:
                # Include overhead resulting from received messages
                for m in db['cc'].find(experiment_id=run['id'], signal="NumReceived"):
                    overhead[m['time']].append(m['value'])  # byte to kilobyte

        times = []
        values = []
        for time in sorted(overhead.keys()):
            times.append(time)
            values.append(sum(overhead[time]))

        label = ', '.join('{}={}'.format(l, run[l]) for l in legend)

        data.append((times, values, label))
    return data


@pickleable
def get_pit_usage(db, experiments, legend):
    data = []
    for experiment in experiments:

        usages = defaultdict(list)

        # Iterate over all seeds of that experiment
        for run in db['experiments'].find(**experiment):
            for m in db['pit'].find(experiment_id=run['id'], signal="PitEntries"):
                usages[m['time']].append(m['value'])

        times = []
        values = []
        for time in sorted(usages.keys()):
            times.append(time)
            values.append(sum(usages[time]) / (len(usages[time] * 5000)))  # 5000 is the PIT size

        label = ', '.join('{}={}'.format(l, run[l]) for l in legend)

        data.append((times, values, label))
    return data


@pickleable
def get_avg_signal_over_time(db, experiments, signal, legend):
    data = []
    for experiment in experiments:

        measurenents = defaultdict(list)

        # Iterate over all seeds of that experiment
        for run in db['experiments'].find(**experiment):
            for m in db['pit'].find(experiment_id=run['id'], signal=signal):
                measurenents[m['time']].append(m['value'])

        times = []
        values = []
        for time in sorted(measurenents.keys()):
            times.append(time)
            values.append(sum(measurenents[time]) / len(measurenents[time]))

        label = ', '.join('{}={}'.format(l, run[l]) for l in legend)

        data.append((times, values, label))
    return data


class DummyDB():
    def query(self, q):
        return []


def get_experiments(db, **kw):
    where_clausel = ' AND '.join(['{}="{}"'.format(t[0], t[1]) for t in kw.iteritems()])
    query = """SELECT DISTINCT topo, mar, ftbm, detection, numClients, clientFrequency, numAttackers, attackersFrequency,
                                  pitLifetime, numMonitors, observationPeriod, tau, gamma, cacheSize, payloadSize, pitSize
                                  FROM experiments
                                  WHERE {}""".format(where_clausel)
    return list(db.query(query))


logging.basicConfig(level=logging.INFO)
logging.basicConfig(level=logging.DEBUG)
logging.getLogger('alembic.migration').setLevel(logging.WARN)
logging.getLogger('dataset.persistence').setLevel(logging.WARN)

make_sure_path_exists(PICKLE_DIR)


def main():
    db = None
    if(len(sys.argv) > 1 and sys.argv[1]):
        # read from db
        logging.info("Reading output directory to database.")
        db = read(sys.argv[1])
    else:
        # read pickled
        logging.info("Using pickled data.")
        db = DummyDB()

    legend = ['detection', 'alpha']

    #
    # No cache
    #

    # AS - MAR0
    experiments = get_experiments(db, topo="AS-3967_delays.ns3.txt", mar=0,
                                  cacheSize=0, numAttackers=14, numMonitors=8,
                                  attackersFrequency=1000)
    exp_name = 'as_mar0_25%_attackers@1000_cache=0'

    plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                   xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                   filename=exp_name + '_global_satisfaction_legitimate', percent=True)
    plot_over_time(get_pit_usage(db, experiments, legend),
                   xlabel='Time [s]', ylabel='PIT Usage',
                   filename=exp_name + '_pit_usage', percent=True)

    # # AS - MAR1
    experiments = get_experiments(db, topo="AS-3967_delays.ns3.txt", mar=1,
                                  cacheSize=0, numAttackers=14, numMonitors=8,
                                  attackersFrequency=1000)
    exp_name = 'as_mar1_25%_attackers@1000_cache=0'

    plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                   xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                   filename=exp_name + '_global_satisfaction_legitimate', percent=True)
    plot_over_time(get_overhead(db, experiments, legend),
                   xlabel='Time [s]', ylabel='Overhead',
                   filename=exp_name + '_overhead')
    plot_over_time(get_pit_usage(db, experiments, legend),
                   xlabel='Time [s]', ylabel='PIT Usage',
                   filename=exp_name + '_pit_usage', percent=True)

    # AS - MAR2
    experiments = get_experiments(db, topo="AS-3967_delays.ns3.txt", mar=2,
                                  cacheSize=0, numAttackers=14, numMonitors=8,
                                  attackersFrequency=500)
    exp_name = 'as_mar2_25%_attackers@500_cache=0'

    plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                   xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                   filename=exp_name + '_global_satisfaction_legitimate', percent=True)
    plot_over_time(get_overhead(db, experiments, legend),
                   xlabel='Time [s]', ylabel='Overhead',
                   filename=exp_name + '_overhead')
    plot_over_time(get_pit_usage(db, experiments, legend),
                   xlabel='Time [s]', ylabel='PIT Usage',
                   filename=exp_name + '_pit_usage', percent=True)

    experiments = get_experiments(db, topo="AS-3967_delays.ns3.txt", mar=2,
                                  cacheSize=0, numAttackers=14, numMonitors=8,
                                  attackersFrequency=1000)
    exp_name = 'as_mar2_25%_attackers@1000_cache=0'

    plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                   xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                   filename=exp_name + '_global_satisfaction_legitimate', percent=True)
    plot_over_time(get_overhead(db, experiments, legend),
                   xlabel='Time [s]', ylabel='Overhead',
                   filename=exp_name + '_overhead')
    plot_over_time(get_pit_usage(db, experiments, legend),
                   xlabel='Time [s]', ylabel='PIT Usage',
                   filename=exp_name + '_pit_usage', percent=True)

    experiments = get_experiments(db, topo="AS-3967_delays.ns3.txt", mar=2,
                                  cacheSize=0, numAttackers=14, numMonitors=8,
                                  attackersFrequency=10000)
    exp_name = 'as_mar2_25%_attackers@10000_cache=0'

    plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                   xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                   filename=exp_name + '_global_satisfaction_legitimate', percent=True)
    plot_over_time(get_overhead(db, experiments, legend),
                   xlabel='Time [s]', ylabel='Overhead',
                   filename=exp_name + '_overhead')
    plot_over_time(get_pit_usage(db, experiments, legend),
                   xlabel='Time [s]', ylabel='PIT Usage',
                   filename=exp_name + '_pit_usage', percent=True)

    #
    # cache = 500
    #

    # AS - MAR0
    experiments = get_experiments(db, topo="AS-3967_delays.ns3.txt", mar=0,
                                  cachesize=500, numAttackers=14, numMonitors=8,
                                  attackersFrequency=1000)
    exp_name = 'as_mar0_25%_attackers@1000_cache=500'

    plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                   xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                   filename=exp_name + '_global_satisfaction_legitimate', percent=True)
    plot_over_time(get_pit_usage(db, experiments, legend),
                   xlabel='Time [s]', ylabel='PIT Usage',
                   filename=exp_name + '_pit_usage', percent=True)

    # # AS - MAR1
    experiments = get_experiments(db, topo="AS-3967_delays.ns3.txt", mar=1,
                                  cachesize=500, numAttackers=14, numMonitors=8,
                                  attackersFrequency=1000)
    exp_name = 'as_mar1_25%_attackers@1000_cache=500'

    plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                   xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                   filename=exp_name + '_global_satisfaction_legitimate', percent=True)
    plot_over_time(get_overhead(db, experiments, legend),
                   xlabel='Time [s]', ylabel='Overhead',
                   filename=exp_name + '_overhead')
    plot_over_time(get_pit_usage(db, experiments, legend),
                   xlabel='Time [s]', ylabel='PIT Usage',
                   filename=exp_name + '_pit_usage', percent=True)

    # AS - MAR2
    experiments = get_experiments(db, topo="AS-3967_delays.ns3.txt", mar=2,
                                  cachesize=500, numAttackers=14, numMonitors=8,
                                  attackersFrequency=1000)
    exp_name = 'as_mar2_25%_attackers@1000_cache=500'

    plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                   xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                   filename=exp_name + '_global_satisfaction_legitimate', percent=True)
    plot_over_time(get_overhead(db, experiments, legend),
                   xlabel='Time [s]', ylabel='Overhead',
                   filename=exp_name + '_overhead')
    plot_over_time(get_pit_usage(db, experiments, legend),
                   xlabel='Time [s]', ylabel='PIT Usage',
                   filename=exp_name + '_pit_usage', percent=True)

if __name__ == '__main__':
    main()
