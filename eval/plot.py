#!/usr/bin/env python
# encoding: utf-8

from __future__ import division
import os
import errno
from itertools import cycle
import matplotlib.pyplot as plt
import logging
from operator import itemgetter

from matplotlib import lines
lines.lineStyles.keys()

FILETYPES = ['png']

styles = {}


def plot_over_time(data, filename, xlabel=None, ylabel=None, percent=False, scale=1, output_dir='plots/'):
    """ Plots data over time.

    Keyword arguments:
    data -- a list of tuples of lists [ (times, values, legend), ... ]
    """

    global styles

    if not data:
        logging.warn("No data for plot {}.".format(filename))
        return

    logging.info("Plotting {}.".format(filename))

    color_cycle = cycle(['#005AA9', '#009D81', '#F5A300', '#E6001A', '#A60084', 'green', 'cyan', 'green'])  # , 'magenta', 'yellow'])
    line_cycle = cycle(['-', 'dashed', 'dotted', '-.', '-', '-', '-', '-'])
    marker_cycle = cycle(['^', 'o', 's', 'p', 'o', 'x', 'v', '*'])  # , '8', '1'])  # lines.MarkerStyle.markers.keys()

    # Sort by legend
    data = sorted(data, key=itemgetter(2))

    for data_item in data:
        times, values, legend = data_item
        values = map(lambda x: x / scale, values)

        if legend in styles:
            marker, color, line = styles[legend]
        else:
            marker = marker_cycle.next()
            color = color_cycle.next()
            line = line_cycle.next()
            styles[legend] = (marker, color, line)

        plt.plot(times, values, label=legend, marker=marker, color=color, linestyle=line)

    if percent:
        # Force y-scale to go from 0 to 1
        axis = plt.axis()
        plt.axis((axis[0], axis[1], 0, 1))

    if(xlabel):
        plt.xlabel(xlabel)

    if(ylabel):
        plt.ylabel(ylabel)

    plt.legend(loc='upper center', bbox_to_anchor=(0.5, 1.2), ncol=2)

    for ft in FILETYPES:
        save(output_dir, filename, ft)

    with open(''.join([output_dir, filename, '.txt']), 'wb') as f:
        for data_item in data:
            f.write(repr(data_item))
            f.write('\n')
    plt.clf()


def save(dir, filename, filetype):
    path = os.path.join(dir, '.'.join([filename, filetype]))
    make_sure_path_exists(os.path.dirname(path))
    plt.savefig(path, bbox_inches="tight")


def make_sure_path_exists(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise
