#ifndef GLOBAL_ROUTING_INFO_H_
#define GLOBAL_ROUTING_INFO_H_

#include "ns3/ndnSIM/ndn.cxx/name.h"

namespace ns3 {
namespace ndn {
namespace fw {

class GlobalRoutingInfo
{
private:
    typedef std::map<uint32_t, std::map<Name, int32_t > >  GlobalRoutingMap;

public:
    GlobalRoutingMap routingMap;

    static void put(uint32_t nodeId, Name prefix, int32_t distance);
    static int32_t get(uint32_t nodeId, Name prefix);

};

} // namespace fw
} // namespace ndn
} // namespace ns3

#endif
