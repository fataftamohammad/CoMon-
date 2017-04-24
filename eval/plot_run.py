#!/usr/bin/env python2
# encoding: utf-8

from collections import defaultdict
import logging
from os import path, chdir, getcwd
import sys

from eval import get_experiments
from plot import plot_over_time
import dataset

from database import eval_filename, read_run

logging.basicConfig(level=logging.INFO)
logging.getLogger('alembic.migration').setLevel(logging.WARN)
logging.getLogger('dataset.persistence').setLevel(logging.WARN)

PIT_SIZE = 5000


def main():
    db = dataset.connect('sqlite:///:memory:')

    filepath = sys.argv[1]

    directory, filename = path.split(filepath)

    old_wd = getcwd()
    chdir(directory)

    run = eval_filename(filename)
    read_run(run, db)

    chdir(old_wd)

    logging.info('Read ' + str(len(db['l3trace']) + len(db['pit']) +
                               len(db['cc'])) + ' measurements.')

    experiment = get_experiments(db, **run)[0]

    if experiment:

        OUTPUT_DIR = 'plots/per_monitor/' + filename + '/'

        run = list(db['experiments'].find(**experiment))[0]

        #
        # PIT usage
        #
        pit_usage_per_node = defaultdict(list)
        for m in db['pit'].find(experiment_id=run['id'], signal='PitEntries', order_by=['time']):
            if m['node'].startswith('monitor'):
                pit_usage_per_node[m['node']].append(m['value'] / PIT_SIZE)

        for monitor, values in pit_usage_per_node.iteritems():
            # I generate the times statically here, because this (hopefully) only
            # used for the simulations I have done...
            times = range(10, 540, 10)
            plot_over_time([(times, values, '')], 'pit_usage_' + monitor, output_dir=OUTPUT_DIR)
            print(monitor, values)

        #
        # Overhead
        #
        overhead_per_node = defaultdict(list)
        traffic_per_node = defaultdict(list)

        if experiment['detection'] in (3, ):
            # Only calculate overhead when CC help is actually used

            # Include overhead resulting from sent messages
            for m in db['cc'].find(experiment_id=run['id'], signal="SizeSent", order_by=['time']):
                overhead_per_node[m['node']].append(m['value'] / 1000)  # byte to kilobyte

            # Include overhead resulting from received messages
            for m in db['cc'].find(experiment_id=run['id'], signal="SizeReceived", order_by=['time']):
                overhead_per_node[m['node']].append(m['value'] / 1000)  # byte to kilobyte

            for m in db['l3trace'].find(experiment_id=run['id'], signal="OutData", order_by=['time']):
                if(m['faceDescr'].count('net') and  # skip local interfaces (faces to apps)
                   m['node'].startswith('server')):
                    traffic_per_node[m['node']].append(m['kilobytes'])

            times = []
            values = []
            for time in sorted(overhead.keys()):
                times.append(time)
                values.append(sum(overhead[time]) / sum(traffic[time]))

            plot_over_time([(times, values, '')], 'overhead_' + monitor, output_dir=OUTPUT_DIR)

if __name__ == '__main__':
    main()
