for i in 2.5
	do
	
	for j in {1..10..1}
	do
		for k in 100
		do
			sleep 20
			sed -i -e "7s/.*/default ns3::ndn::CnmrClient::s \"$i\"/" cnmr-config.txt
			sed -i -e "27s/.*/global CacheSize \"$j\"/" cnmr-config.txt
			sed -i -e "10s/.*/default ns3::ndn::CnmrClient::Frequency \"$k\"/" cnmr-config.txt
			./waf --run=ndn-cnmr & done
	done
done
# This is for the no Attack Case , It works Parallel and needs 24 Cores
