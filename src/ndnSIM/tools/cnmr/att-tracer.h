#ifndef ATT_TRACER_H_
#define ATT_TRACER_H_

#include <fstream>
#include <string>

namespace ns3
{
	namespace ndn
	{
		class AttackTracer
		{
		public:
			static void
			Write(std::string s,int i,bool print)
			{
				static std::string filename,t1,t2,t3;
				static unsigned long long ca,cb,cc;
				if(i==0)
					 filename = s,ca=cb=cc=0,t1=filename+"ServerReceivedPackets",t2=filename+"ClientIssuedPackets",t3=filename+"CacheHits";
				else if(i==1)
				{
					ca++;
					if(!print)
						return;
					std::ofstream a(t1.c_str());
					a << ca <<"\n";
					a.close();
				}	
				else if(i==2)
				{
					cb++;
					if(!print)
						return;
					std::ofstream a(t2.c_str());
					a << cb <<"\n";
					a.close();
				}
				else if(i==3)
				{
					cc++;
					if(!print)
						return;
					std::ofstream a(t3.c_str());
					a << cc <<"\n";
					a.close();
				}
			}
				
		};
	}
}
#endif