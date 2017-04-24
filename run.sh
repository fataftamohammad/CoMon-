#!/bin/bash

#NS_LOG=ndn.fw.MonitorAwareRouting:ndn.fw.ForwardingStrategy:ndn.fw:ndn.CnmrClient:ndn.CnmrServer: python2 waf -j 2 --run=ndn-cnmr $@
python2 waf -j 2 --run=ndn-cnmr $@
