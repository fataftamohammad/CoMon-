for k in 600 1200 1800
do
	for i in 0.9 1.5 2.5
	do
		for j in 10 30
		do
			for z in 5 10 50 100 1000
			do
					sleep 40
					sed -i -e "7s/.*/default ns3::ndn::CnmrClient::s \"$i\"/" cnmr-config.txt
					sed -i -e "27s/.*/global CacheSize \"$j\"/" cnmr-config.txt
					sed -i -e "11s/.*/default ns3::ndn::CnmrFloodingAttacker::MinSeq \"$z\"/" cnmr-config.txt
					sed -i -e "10s/.*/default ns3::ndn::CnmrFloodingAttacker::Frequency \"$k\"/" cnmr-config.txt
					sed -i -e "17s/.*/default ns3::ndn::fw::MonitorAwareRouting::tau \"$z\"/" cnmr-config.txt
					./waf --run=ndn-cnmr &	done
		done
	done
done
