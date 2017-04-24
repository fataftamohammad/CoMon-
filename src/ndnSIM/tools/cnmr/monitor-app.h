// monitor-app.h

#ifndef MONITOR_APP_H_
#define MONITOR_APP_H_

#include "ns3/ndn-app.h"
#include "ns3/ndn-pit.h"
#include "ns3/nstime.h"
#include "ns3/ndnSIM/ndn.cxx/name.h"
#include "../src/ndnSIM/model/fw/monitor-aware-routing.h"
#include <map>
namespace ns3 {
namespace ndn {

typedef struct CNMRReport {
    uint32_t interestsReceived;
    uint32_t cacheHits;
    uint32_t interestsSatisfied;
    uint32_t interestsTimedOut;

    // double pitUsage;
    // uint32_t pitEntries; // the current number of PIT entries

    // fw::MonitorAwareRouting::PerNameCounter receivedPerName;
    // fw::MonitorAwareRouting::PerNameCounter satisfiedPerName;
    // fw::MonitorAwareRouting::PerNameCounter timedOutPerName;
    fw::MonitorAwareRouting::PerNameCounter timedOutEntriesPerName;
    std::map<Name,uint32_t> requestsPerName;

} CNMRReport;

class MonitorApp : public ndn::App
{
public:
    static const uint32_t FLAG = 500;

    static TypeId GetTypeId ();
    virtual void StartApplication ();
    virtual void StopApplication ();
    virtual void OnInterest (Ptr<const ndn::Interest> interest);
    virtual void OnData (Ptr<const ndn::Data> contentObject);

private:
    Name monitorPrefix;
    Ptr<Node> node;
    Ptr<ndn::fw::MonitorAwareRouting> mar;

    Time m_observationPeriod;

    TracedCallback<Ptr<const Interest>, bool, bool > interestConsumedTrace;

    // Timers
    void onTimerObservationPeriod(void);

    uint32_t detection;
    int interests_received;
    int cache_hits;
    std::map<Name,uint32_t> requestsPerName;


};

} // namespace ndn
} // namespace ns3

#endif // MONITOR_APP_H_
