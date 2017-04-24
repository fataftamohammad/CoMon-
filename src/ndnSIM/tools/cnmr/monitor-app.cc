#include "monitor-app.h"
#include "cc.h"
#include "ns3/ndnSIM/model/fw/monitor-aware-routing.h"
#include "ns3/ndnSIM/utils/ndn-fw-hop-count-tag.h"

#include "ns3/core-module.h"
#include "ns3/ndnSIM-module.h"
#include "ns3/ptr.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/packet.h"
#include "ns3/ndn-l3-protocol.h"

#include "ns3/ndn-app-face.h"
#include "ns3/ndn-interest.h"
#include "ns3/ndn-data.h"

#include "ns3/ndn-fib.h"
#include "ns3/random-variable.h"

#include "ns3/ndn-app-face.h"
#include "ns3/ndn-l3-protocol.h"

#include <boost/foreach.hpp>

NS_LOG_COMPONENT_DEFINE ("MonitorApp");

namespace ns3 {
namespace ndn {

NS_OBJECT_ENSURE_REGISTERED (MonitorApp);

// register NS-3 type
TypeId MonitorApp::GetTypeId ()
{
    static TypeId tid = TypeId ("MonitorApp")
        .SetParent<App> ()
        .AddConstructor<MonitorApp> ()

        .AddTraceSource ("InterestConsumed",  "InterestConsumed",  MakeTraceSourceAccessor (&MonitorApp::interestConsumedTrace))

        .AddAttribute("ObservationPeriod", "Interval at which a monitor reports to the CC",
                      TimeValue (Seconds (2)),
                      MakeTimeAccessor (&MonitorApp::m_observationPeriod),
                      MakeTimeChecker ());
  return tid;
}

void MonitorApp::StartApplication ()
{
  // INLINED ndn::App::StartApplication ();
  NS_LOG_FUNCTION_NOARGS ();

  NS_ASSERT (m_active != true);
  m_active = true;

  node = GetNode();

  NS_ASSERT_MSG (node->GetObject<L3Protocol> () != 0,
                 "Ndn stack should be installed on the node " << node);

  // step 1. Create a face
  m_face = CreateObject<AppFace> (/*Ptr<App> (this)*/this);

  // ---------------------------------------------------------------------------------------------
  // CHANGE: Set this flag to be able to identify the face of this app in the forwarding strategy
  m_face->SetFlags(FLAG);
  // END CHANGE
  // ---------------------------------------------------------------------------------------------

  // step 2. Add face to the Ndn stack
  node->GetObject<L3Protocol> ()->AddFace (m_face);

  // step 3. Enable face
  m_face->SetUp (true);
  // END INLINED ndn::App::StartApplication ();

  Ptr<Name> prefix = Create<Name> ();
  prefix->append ("localmonitor");

  mar = node->GetObject<ndn::fw::MonitorAwareRouting>();

  /////////////////////////////////////////////////////////////////////////////
  // Creating FIB entry that ensures that we will receive incoming Interests //
  /////////////////////////////////////////////////////////////////////////////

  // Get FIB object
  Ptr<ndn::Fib> fib = node->GetObject<ndn::Fib> ();
  Ptr<fib::Entry> fibEntry = fib->Add (*prefix, m_face, 0);
  fibEntry->UpdateStatus (m_face, fib::FaceMetric::NDN_FIB_GREEN);

  Simulator::Schedule(m_observationPeriod, &MonitorApp::onTimerObservationPeriod, this);

    // Remove FIB entries to other monitors (monitors don't need that)
    monitorPrefix.append("monitor");
    fib->Remove(&monitorPrefix);

    // Share distances to servers to global module so that other routers can access it
    for (Ptr<fib::Entry> entry = fib->Begin (); entry != fib->End (); entry = fib->Next (entry))
    {
        if(entry->GetPrefix().size() > 1 && monitorPrefix.compare(entry->GetPrefix().getPrefix(0, 2)) != 0)
        {
            // Skip FIB entries to other monitors. They are not of interest here.
            continue;
        }

        BOOST_FOREACH (const fib::FaceMetric &metricFace, entry->m_faces.get<fib::i_metric> ())
        {
            if(metricFace.GetRoutingCost() != 0)
            {
                // If routing cost is zero, this is a local app -> don't report that
                fw::GlobalRoutingInfo::put(node->GetId(), entry->GetPrefix(), metricFace.GetRoutingCost());
            }
        }
    }

    UintegerValue v_Detection;
    mar->GetAttribute("Detection", v_Detection);
    detection = v_Detection.Get();
    interests_received = 0;
    cache_hits = 0;
}

void MonitorApp::StopApplication ()
{
    // cleanup ndn::App
    App::StopApplication ();
}
void MonitorApp::OnInterest (Ptr<const Interest> interest)
{
    // printf("app %s %d \n",interest->GetScope());
    // printf("fw %s\n",interest->GetName().toUri().c_str());

    App::OnInterest (interest);
    // if(interest->GetScope() != (int8_t)0xFF)//dont' monitor it
    // {
      // printf("hereeeeeeeeeeeeeeeeeeee\n");
      // return;
    //     FwHopCountTag hopCountTag;
    //     interest->GetPayload ()->PeekPacketTag (hopCountTag);

    //     Ptr<Name> nameWithSequence = Create<Name> (interest->GetName ());

    //     Ptr<Interest> newInterest = Create<Interest> ();
    //     newInterest->SetNonce (interest->GetNonce ());
    //     newInterest->SetName (interest->GetName ());
    //     newInterest->SetInterestLifetime (interest->GetInterestLifetime ());
    //     newInterest->SetMonitored(0);
    //     newInterest->SetServed(0);
    //     newInterest->GetPayload()->AddPacketTag(hopCountTag);


    //     m_face->ReceiveInterest (newInterest);
    //     return;
    // }

    if(interest->GetMonitored() > 1)
        // Don't monitor an already observed interest
        return;
    ns3::ndn::Name name = interest->GetName ();
    interests_received++;
    requestsPerName[interest->GetName()]++;
    NS_LOG_INFO ("Received Interest packet for " << name << " (monitored=" << interest->GetMonitored()
          << " served=" << interest->GetServed() << ")");

    if(interest->GetServed() == 0)
    {

        // NS_LOG_INFO("Monitored interest but it's not served. Forwarding...");

        FwHopCountTag hopCountTag;
        interest->GetPayload ()->PeekPacketTag (hopCountTag);

        Ptr<Name> nameWithSequence = Create<Name> (interest->GetName ());

        Ptr<Interest> newInterest = Create<Interest> ();
        newInterest->SetNonce (interest->GetNonce ());
        newInterest->SetName (interest->GetName ());
        newInterest->SetInterestLifetime (interest->GetInterestLifetime ());
        newInterest->SetMonitored(1);
        newInterest->SetServed(0);
        newInterest->GetPayload()->AddPacketTag(hopCountTag);

        m_face->ReceiveInterest (newInterest);
    }
    else
    {
        cache_hits++;
        // This interest is served and (now) monitored. That means it will be consumed be this node.
        // Hence this node has to print the hops.
        interestConsumedTrace(interest, true, true);
    }
}

void MonitorApp::OnData (Ptr<const Data> contentObject)
{
    if(contentObject->GetSignature()==3)
    {
      // printf("cache hit after!\n");
      cache_hits++;
    }
    // else
    //   printf("from server!\n");
    App::OnData (contentObject);
    NS_LOG_INFO ("Receiving Data packet for " << contentObject->GetName ());
}

void MonitorApp::onTimerObservationPeriod(void)
{
    if(detection >= 3)
    {
        // Only report to CC when a detection scheme with CC help is used
        CNMRReport report;
        report.cacheHits = cache_hits;
        report.interestsReceived = interests_received;
        report.requestsPerName = requestsPerName;
        // Currently unused
        // report.pitEntries = mar->getPitEntries();
        // report.pitUsage = mar->getPitUsage();
        // printf("%.3f interests recived: %d, cache_hits: %d \n",Simulator::Now().GetSeconds(), interests_received,cache_hits);

        // printf("OnTimerObservatioinPeriod: interestsSatisfied %d, report.interestsTimedOut %d\n",mar->getUnmonitoredSatisfied(),mar->getUnmonitoredTimedOut());
        report.interestsSatisfied = mar->getUnmonitoredSatisfied();
        report.interestsTimedOut = mar->getUnmonitoredTimedOut();

        // report.timedOutEntriesPerName = mar->getEntriesPerNameUnmonitored();

        // if(report.timedOutEntriesPerName.size() > 0)
        CC::report(node, report);
    }
    interests_received=cache_hits = 0;
    requestsPerName.clear();
    // Reset the stats at this monitor node
    mar->resetStats();

    // Reschedule
    Simulator::Schedule(m_observationPeriod, &MonitorApp::onTimerObservationPeriod, this);
}

} // namespace ndn
} // namespace ns3
