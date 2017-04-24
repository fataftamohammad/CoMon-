#ifndef ROUTER_APP_H_
#define ROUTER_APP_H_

#include "ns3/ndn-app.h"
#include "ns3/nstime.h"
#include "ns3/ndnSIM/model/fw/monitor-aware-routing.h"

namespace ns3 {
namespace ndn {

class RouterApp : public ndn::App
{
public:
    static TypeId GetTypeId ();
    virtual void StartApplication ();

private:
    Ptr<ndn::fw::MonitorAwareRouting> mar;

    // An event to schedule the clearing of the stats in routers that don't have a monitor app
    // (EWMA)
    EventId m_resetStats;

    Time m_observationPeriod;

    void onTimerResetStats(void);
};

} // namespace ndn
} // namespace ns3

#endif // ROUTER_APP_H_
