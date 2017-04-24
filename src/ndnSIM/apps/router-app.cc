#include "router-app.h"
#include "ns3/core-module.h"
#include "ns3/ndnSIM-module.h"
#include "ns3/ptr.h"
#include "ns3/simulator.h"

NS_LOG_COMPONENT_DEFINE ("RouterApp");

namespace ns3 {
namespace ndn {

NS_OBJECT_ENSURE_REGISTERED (RouterApp);

TypeId RouterApp::GetTypeId ()
{
    static TypeId tid = TypeId ("RouterApp")
        .SetParent<App>()
        .AddConstructor<RouterApp>()
        .AddAttribute("ObservationPeriod", "Interval at which to reset stats",
                      TimeValue (Seconds (1)),
                      MakeTimeAccessor (&RouterApp::m_observationPeriod),
                      MakeTimeChecker ());
    return tid;
}

void RouterApp::StartApplication ()
{
    App::StartApplication();
    // mar = GetNode()->GetObject<ndn::fw::BestRoute>();
    // m_resetStats = Simulator::Schedule (m_observationPeriod, &RouterApp::onTimerResetStats, this);
}

void RouterApp::onTimerResetStats(void)
{
    // mar->resetStats();
    // Simulator::Schedule(m_observationPeriod, &RouterApp::onTimerResetStats, this);
}

} // namespace ndn
} // namespace ns3
