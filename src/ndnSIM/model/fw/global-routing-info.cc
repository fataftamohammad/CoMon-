#include "global-routing-info.h"
#include "ns3/log.h"
#include "ns3/simulation-singleton.h"

NS_LOG_COMPONENT_DEFINE ("GlobalRoutingInfo");

namespace ns3 {
namespace ndn {
namespace fw {

void GlobalRoutingInfo::put(uint32_t nodeId, Name prefix, int32_t distance)
{
    NS_LOG_DEBUG("Node " << nodeId << " reported route to " << prefix << " for "  << distance);
    SimulationSingleton<GlobalRoutingInfo>::Get()->routingMap[nodeId][prefix] = distance;
}

int32_t GlobalRoutingInfo::get(uint32_t nodeId, Name prefix)
{
    NS_LOG_DEBUG("Query route to " << prefix << " from monitor" << nodeId);
    return SimulationSingleton<GlobalRoutingInfo>::Get()->routingMap[nodeId][prefix];
}

} // namespace fw
} // namespace ndn
} // namespace ns3
