#ifndef CNMR_FW_H_
#define CNMR_FW_H_

#include "ndn-forwarding-strategy.h"
#include "ns3/node.h"
#include "ns3/log.h"
#include "ns3/ndnSIM/ndn.cxx/name.h"
#include "ns3/uinteger.h"
#include "ns3/traced-callback.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/random-variable.h"
#include <set>

namespace ns3 {
namespace ndn {
namespace fw {

class MonitorAwareRouting : public ForwardingStrategy
{

private:
    typedef ForwardingStrategy super;
    std::set<Name> not_for_cache;
    std::map<Name,uint32_t> content_monitorID;
    // std::set<Name> not_for_cache;
public:

    void setNotForCache(std::set<Name> _not_for_cache);
    void setContentMonitorID(std::map<Name,uint32_t> _content_monitorID);
    typedef std::map<Ptr<Face>, uint32_t> PerFaceCounter;
    typedef std::map<Name, uint32_t> PerNameCounter;
    typedef std::map<Ptr<Face>, PerNameCounter> PerFacePerNameCounter;

    typedef std::map<Ptr<Face>, double> PerFaceStat;
    typedef std::map<Name, double> PerNameStat;

    MonitorAwareRouting();

    enum Mode {OPPORTUNISTIC, MAR1, MAR2, MAR3};

    static TypeId GetTypeId();

    virtual void AddFace (Ptr< Face > face);
    virtual void OnInterest (Ptr<Face> face, Ptr<Interest> interest);

    static std::string GetLogName();

    void resetStats();

    uint32_t getPitEntries();

    uint32_t getUnmonitoredSatisfied();
    uint32_t getUnmonitoredTimedOut();

    double getPitUsage();
    double getSatisfactionRatioUnmonitored(Ptr<Face> inFace, Name name);

    MonitorAwareRouting::PerNameCounter getEntriesPerNameUnmonitored();
    MonitorAwareRouting::PerNameCounter getTimedOutEntriesPerNameUnmonitored();

    void setMaliciousPrefixes(std::set<Name> prefixes);

    bool getHasMonitor();
    void setHasClient();
    void setHasServer();

protected:
    virtual void PropagateInterest (Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry);
    virtual bool DoPropagateInterest (Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry);
    virtual bool CanSendOutInterest (Ptr<Face> inFace, Ptr<Face> outFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry);
    virtual void WillSatisfyPendingInterest (Ptr<Face> inFace, Ptr<pit::Entry> pitEntry);
    virtual void DidSendOutInterest(Ptr<Face> inFace, Ptr<Face> outFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry);
    virtual bool TrySendOutInterest (Ptr<Face> inFace, Ptr<Face> outFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry);

    static LogComponent g_log;

    bool hasMonitor;
    bool hasAttacker;
    bool hasClient;
    bool hasServer;

    bool m_ftbm;
    enum Mode m_mode;

private:
    //
    // Utils
    //
    Name monitorPrefix;
    Ptr<Face> localMonitorFace;
    Ptr<Face> nearestMonitorFace;
    std::map<Name, Ptr<Face> > routingTableMAR2;

    Ptr<ndn::Pit> pit;
    int pitMaxSize;

    //
    // Stats
    //
    PerFaceCounter satisfiedPerFace;
    PerFaceCounter timedOutPerFace;

    PerFaceCounter satisfiedUnmonitoredPerFace;
    PerFaceCounter timedOutUnmonitoredPerFace;

    PerNameCounter satisfiedUnmonitoredPerName;
    PerNameCounter timedOutUnmonitoredPerName;

    PerFacePerNameCounter satisfiedUnmonitoredPerFacePerName;
    PerFacePerNameCounter timedOutUnmonitoredPerFacePerName;

    // The malicious prefixes as identified by the CC
    std::set<Name> maliciousPrefixes;

    // The prefixes of which PIT entries have timedout (per face)
    std::map<Ptr<Face>, std::set<Name> > timedOutPrefixesPerFace;
    std::set<Name> timedOutPrefixes;

    // To keep tack of content names that have been satisfied previously
    std::set<Name> satisfiedNames;

    // To keep track of content names that have been requested before in this observation period
    std::set<Name> requestedNames;

    // std::set<Name> satisfiedNames is only reset every 10 observation periods. this is just a
    // counter to keep track of that.
    int resetRound;

    int satisfiedUnmonitored;
    int timedOutUnmonitored;

    // To keep track of PIT entries that have been monitored by this CNMR first (per face)
    std::map<Ptr<Face>, std::set<Ptr<pit::Entry> > > locallyMonitored;

    bool DoPropagateInterestOpportunistic (Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry);
    bool DoPropagateInterestBestRoute (Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry);
    bool DoPropagateInterestMAR1 (Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry);
    bool DoPropagateInterestMAR2 (Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry);
    bool DoPropagateInterestMAR3 (Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry);

    void WillEraseTimedOutPendingInterest(Ptr<pit::Entry> pitEntry);

    bool CanAcceptInterest(Ptr<Face> inFace, Ptr<Interest> interest);
    bool recordStats();

    TracedCallback<uint32_t> entriesSatisfiedBeforeTrace;
    TracedCallback<uint32_t> maliciousRequestedMultiTrace;
    TracedCallback<double, uint32_t> pitUsageTrace;
    TracedCallback<Ptr<const Interest>, bool, bool > interestConsumedTrace;
    TracedCallback<uint32_t, Name> RequestedContentInterface;

    // The used detection scheme
    uint32_t detection;

    // The minimum PIT usage for the dectecion schemes to kick in
    double tau;

    UniformVariable rnd_Drop;

};

} // namespace fw
} // namespace ndn
} // namespace ns3

#endif
