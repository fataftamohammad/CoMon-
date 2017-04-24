#include "monitor-aware-routing.h"
#include "ns3/core-module.h"
#include "ns3/enum.h"
#include "ns3/ndn-interest.h"
#include "ns3/ndn-data.h"
#include "ns3/ndn-face.h"
#include "ns3/ndn-pit.h"
#include "ns3/ndn-pit-entry.h"
#include "ns3/ndn-app-face.h"
#include "ns3/ndn-content-store.h"
#include "ns3/ndnSIM/utils/ndn-fw-hop-count-tag.h"
#include "global-routing-info.h"
#include "ns3/channel.h"
#include "ns3/ndn-net-device-face.h"
#include "ns3/point-to-point-module.h"

#include "../../tools/cnmr/monitor-app.h"
#include "ns3/ndnSIM/apps/cnmr-flooding-attacker.h"

#include <limits.h>
#include <iostream>
#include <memory>

#include <boost/ref.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/lambda/bind.hpp>
#include "ns3/ndnSIM/model/cs/content-store-impl.h"
#include "ns3/pointer.h"

namespace ll = boost::lambda;

namespace ns3 {
namespace ndn {
namespace fw {

NS_OBJECT_ENSURE_REGISTERED (MonitorAwareRouting);

LogComponent MonitorAwareRouting::g_log = LogComponent (MonitorAwareRouting::GetLogName ().c_str ());

std::string MonitorAwareRouting::GetLogName()
{
    return super::GetLogName ()+".MonitorAwareRouting";
}

TypeId MonitorAwareRouting::GetTypeId()
{
    static TypeId tid = TypeId ("ns3::ndn::fw::MonitorAwareRouting")
        .SetGroupName ("Ndn")
        .SetParent <ForwardingStrategy> ()
        .AddConstructor <MonitorAwareRouting> ()

        .AddTraceSource ("PITUsage",  "PITUsage",  MakeTraceSourceAccessor (&MonitorAwareRouting::pitUsageTrace))
        .AddTraceSource ("EntriesSatisfiedBefore",  "EntriesSatisfiedBefore",  MakeTraceSourceAccessor (&MonitorAwareRouting::entriesSatisfiedBeforeTrace))
        .AddTraceSource ("MaliciousRequestedMulti",  "MaliciousRequestedMulti",  MakeTraceSourceAccessor (&MonitorAwareRouting::maliciousRequestedMultiTrace))
        .AddTraceSource ("InterestConsumed",  "InterestConsumed",  MakeTraceSourceAccessor (&MonitorAwareRouting::interestConsumedTrace))
        .AddTraceSource ("RequestedContentInterface",  "RequestedContentInterface",  MakeTraceSourceAccessor (&MonitorAwareRouting::RequestedContentInterface))

        .AddAttribute("FTBM", "Enable/Disable 'Forward till be monitoredl'",
                BooleanValue(true),
                MakeBooleanAccessor (&MonitorAwareRouting::m_ftbm),
                MakeBooleanChecker ())

        .AddAttribute ("Detection", "Used detection scheme",
                StringValue ("0"),
                MakeUintegerAccessor (&MonitorAwareRouting::detection),
                MakeUintegerChecker<uint32_t> (0, 5))

        .AddAttribute("Mode", "MAR mode (opportunistic/MAR-1/MAR-2/MAR-3)",
                EnumValue(MonitorAwareRouting::MAR1),
                MakeEnumAccessor (&MonitorAwareRouting::m_mode),
                MakeEnumChecker (MonitorAwareRouting::OPPORTUNISTIC, "0",
                    MonitorAwareRouting::MAR1, "1",
                    MonitorAwareRouting::MAR2, "2"))
                    /* MonitorAwareRouting::MAR3, "3")) */

        .AddAttribute ("tau", "The minimum PIT usage for the dectecion schemes to kick in",
                StringValue ("0.3"),
                MakeDoubleAccessor (&MonitorAwareRouting::tau),
                MakeDoubleChecker<double> ())
        ;
    return tid;
}

MonitorAwareRouting::MonitorAwareRouting()
{
    monitorPrefix.append("monitor");
    hasMonitor = false;
    hasAttacker = false;
    hasServer = false;
    hasClient = false;
    resetStats();
    resetRound = 0;
}

void MonitorAwareRouting::AddFace(Ptr<Face> face)
{
    super::AddFace(face);
    if(face->GetFlags() == MonitorApp::FLAG)
    {
        hasMonitor = true;
        localMonitorFace = face;
        // int id = localMonitorFace->GetNode()->GetId();
        // monitorPrefix.append(boost::lexical_cast<std::string>(id));
        // std::cout<<monitorPrefix<<std::endl;
    }

    if(face->GetFlags() == CnmrFloodingAttacker::FLAG)
    {
        hasAttacker = true;
    }

    if(pit == 0)
    {
        // Get PIT object and its maximum size
        pit = GetObject<ndn::Pit> ();
        StringValue svPitSize;
        pit->GetAttribute("MaxSize", svPitSize);
        pitMaxSize = atoi(svPitSize.Get().c_str());
    }

}

bool MonitorAwareRouting::CanSendOutInterest (Ptr<Face> inFace, Ptr<Face> outFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry)
{
    // Normal routing would not allow routing back to the same face as the interest arrived. In MAR
    // this is needed sometimes, if the current node is a monitor and the interest is just forwarded
    // here to be monitored. It might then be the shortest way to just forward the interest back.
    // That is why it is checked here whether this node is a monitor node.
    // Hence, outFace == inFace is only invalid when this node is not a monitor and the scenario
    // described above does not hold.
    if (outFace == inFace && !hasMonitor)
    {
        return false; // same face as incoming, don't forward
    }

    if(hasAttacker)
    {
        // Attacker don't care
        return true;
    }

    pit::Entry::out_iterator outgoing = pitEntry->GetOutgoing ().find (outFace);

    if (outgoing != pitEntry->GetOutgoing ().end ())
    {
        if (!m_detectRetransmissions)
            return false; // suppress
        else if (outgoing->m_retxCount >= pitEntry->GetMaxRetxCount ())
        {
            // NS_LOG_DEBUG ("Already forwarded before during this retransmission cycle (" <<outgoing->m_retxCount << " >= " << pitEntry->GetMaxRetxCount () << ")");
            return false; // already forwarded before during this retransmission cycle
        }
    }

    return true;
}

/*
 * When a detection scheme is used the nodes decide here whether they accept a packet or not.
 */
bool MonitorAwareRouting::CanAcceptInterest(Ptr<Face> inFace, Ptr<Interest> interest)
{
    if(hasClient || hasAttacker || hasServer)
        return true;

    ns3::ndn::Name name = interest->GetName();
    Name prefix = name.getSubName(0, 1);
    bool isMonitored = interest->GetMonitored() != 0;

    switch(detection)
    {
        case 0:
        {
            // no detection/reaction -> accept all packets
            return true;
        }

        case 1:
        {
            if(hasMonitor
                    && !isMonitored // has not been monitored by another CNMR
                    && getPitUsage() > tau // PIT usage above threshold
                    && timedOutPrefixesPerFace[inFace].find(prefix) != timedOutPrefixesPerFace[inFace].end()) // isMaliciousPrefix?
            {
                double p_Drop = getSatisfactionRatioUnmonitored(inFace, prefix);
                double rnd = rnd_Drop.GetValue();
                if(rnd > p_Drop)
                {
                    // Drop interest with probability P(p_Drop)
                    return false;
                }
            }
            return true;
        }

        case 2:
        {
            if(hasMonitor
                    && !isMonitored // has not been monitored by another CNMR
                    && getPitUsage() > tau // PIT usage above threshold
                    && timedOutPrefixesPerFace[inFace].find(prefix) != timedOutPrefixesPerFace[inFace].end() // isMaliciousPrefix?
                    && satisfiedNames.find(name) == satisfiedNames.end() // content name has been satisfied before
                    && requestedNames.find(name) == requestedNames.end()) // content name has been requested before
            {
                double p_Drop = getSatisfactionRatioUnmonitored(inFace, prefix);
                double rnd = rnd_Drop.GetValue();
                if(rnd > p_Drop)
                {
                    // Drop interest with probability P(p_Drop)
                    return false;
                }
            }
            return true;
        }

        case 3:
        {
            if(hasMonitor
                    && !isMonitored // has not been monitored by another CNMR
                    && ((getPitUsage() > tau // PIT usage above threshold
                    && timedOutPrefixesPerFace[inFace].find(prefix) != timedOutPrefixesPerFace[inFace].end()) // isMaliciousPrefix?
                        || maliciousPrefixes.find(prefix) != maliciousPrefixes.end()) // OR is malicious prefix identified by CC, regardless of PIT usage
                    && satisfiedNames.find(name) == satisfiedNames.end() // content name has been satisfied before
                    && requestedNames.find(name) == requestedNames.end()) // content name has been requested before
            {
                double p_Drop = getSatisfactionRatioUnmonitored(inFace, prefix);
                double rnd = rnd_Drop.GetValue();
                if(rnd > p_Drop)
                {
                    // Drop interest with probability P(p_Drop)
                    return false;
                }
            }
            return true;
        }

        default:
        {
            return true;
        }
    }
}

void MonitorAwareRouting::OnInterest(Ptr<Face> inFace, Ptr<Interest> interest)
{
    ns3::ndn::Name name = interest->GetName();
    Name prefix = name.getSubName(0, 1);

    NS_LOG_DEBUG ("Received Interest packet for " << name << " (monitored=" << interest->GetMonitored()
          << " served=" << interest->GetServed() << ")");

    if(!CanAcceptInterest(inFace, interest))
    {
        m_dropInterests (interest, inFace);

        // Record all requested names, if the interest is accepted or not
        requestedNames.insert(name);

        maliciousRequestedMultiTrace(requestedNames.size());
        return;
    }

    requestedNames.insert(name);
    maliciousRequestedMultiTrace(requestedNames.size());

    bool interestMonitored = interest->GetMonitored() != 0;
    bool interestServed = interest->GetServed() != 0;

    if((interestMonitored || !m_ftbm) && interestServed)
    {
        interestConsumedTrace(interest, false, true);
        return;
    }

    Ptr<pit::Entry> pitEntry = m_pit->Lookup (*interest);

    bool similarInterest = true;
    if (pitEntry == 0)
    {
        similarInterest = false;
        pitEntry = m_pit->Create(interest);
        if (pitEntry == 0)
        {
            FailedToCreatePitEntry (inFace, interest);
            return;
        }
    }

    bool isDuplicated = true;
    if (!pitEntry->IsNonceSeen (interest->GetNonce ()))
    {
        pitEntry->AddSeenNonce (interest->GetNonce ());
        isDuplicated = false;
    }

    if(!interestServed && !isDuplicated)
    {
        m_inInterests (interest, inFace);

        if(recordStats())
        {
            if(hasMonitor && !interestMonitored)
            {
                // Monitor apps count previously unmonitored interests seperately
                locallyMonitored[inFace].insert(pitEntry);
            }
        }
    }

    if(!hasAttacker && isDuplicated && interestServed && interestMonitored)
    {
        // printf("here1!!!\n");
        DidReceiveDuplicateInterest (inFace, interest, pitEntry);
        return;
    }
    // if(hasMonitor)
    // {
    // // printf("fw %s\n",interest->GetName().toUri().c_str());

    //     uint32_t id1 = localMonitorFace->GetNode()->GetId();
    //     if(content_monitorID.find(interest->GetName()) != content_monitorID.end() && id1 != content_monitorID[interest->GetName()])
    //     {
    //         // printf("should print now\n");
    //         interest -> SetScope((int8_t)0xFE);//0xFE don't monitor it!!
    //     }
    //     else 
    //         interest -> SetScope((int8_t)0xFF);//0xFF monitor it!!

    // }

    if (not_for_cache.find(name)==not_for_cache.end())
    // if(false)
    {
        Ptr<Data> contentObject;
        contentObject = m_contentStore->Lookup (interest);
        if(hasMonitor)
        {
            uint32_t id1 = localMonitorFace->GetNode()->GetId();

            if(content_monitorID.find(interest->GetName()) != content_monitorID.end() && id1 != content_monitorID[interest->GetName()]) //set it as if it were fucking served.
            {
              contentObject = Create<Data> (Create<Packet> (1024));//m_virtualPayloadSize
              Ptr<Name> dataName = Create<Name> (interest->GetName());


              contentObject->SetName (dataName);

              // data->SetFreshness (TimeValue (Seconds (0)));//m_freshness
              contentObject->SetTimestamp (Simulator::Now());

              contentObject->SetSignature (3);//2 from producer, 3 from cache.
              
                // printf("got from the monitor ;)\n");
                // printf("should print now\n");
                // interest -> SetScope((int8_t)0xFE);//0xFE don't monitor it!!
            }
        }
        // DynamicCast<ns3::ndn::cs::ContentStoreImpl,ns3::ndn::cs::ContentStoreImpl>(m_contentStore);
        // DynamicCast<PointToPointNetDevice> (m_contentStore);
        // (ns3::ndn::cs::ContentStoreImpl>* x;
        // printf("waiting...\n");
        // m_contentStore->attackDetection (name);


        // DynamicCast<ndn::cs::ContentStoreImpl<ns3::ndn::ndnSIM::lru_policy_traits> > (m_contentStore);
        // if(not_for_cache.find(name)!=not_for_cache.end())
        //     printf("NOT FOR CACHE!!!%s\n",name.toUri().c_str());
        if (contentObject != 0 && !interestServed)
        {


            FwHopCountTag hopCountTag;
            if (interest->GetPayload ()->PeekPacketTag (hopCountTag))
            {
                contentObject->GetPayload ()->AddPacketTag (hopCountTag);
            }

            if(!isDuplicated)
            {
                //Set contentobject as not served from server

                // contentObject->fromServer = false;
                if(!hasServer)
                    contentObject->SetSignature(3);
                pitEntry->AddIncoming (inFace/*, Seconds (1.0)*/);

                Ptr<const Interest> interest = pitEntry->GetInterest();

                // Do data plane performance measurements
                WillSatisfyPendingInterest (0, pitEntry);

                // Actually satisfy pending interest
                SatisfyPendingInterest (0, contentObject, pitEntry);

                if(m_ftbm && !interestMonitored)
                {
                    NS_LOG_DEBUG("Served interest from cache but it's not monitored. Forwarding...");

                    // If FTMB monitored is enabled and this interest has not been monitored before, we
                    // have to forward it. Thus we create a copy of this interest and forward it to this
                    // nodes routing module

                    FwHopCountTag hopCountTag;
                    interest->GetPayload ()->PeekPacketTag (hopCountTag);

                    Ptr<Name> nameWithSequence = Create<Name> (interest->GetName ());

                    Ptr<Interest> newInterest = Create<Interest> ();
                    newInterest->SetNonce (interest->GetNonce ());
                    newInterest->SetName (interest->GetName ());
                    newInterest->SetInterestLifetime (interest->GetInterestLifetime ());
                    newInterest->SetServed(1);
                    newInterest->GetPayload()->AddPacketTag(hopCountTag);

                    OnInterest(inFace, newInterest);
                }
                else
                {
                    // Print the hops (including the last hop) to logfile
                    interestConsumedTrace(interest, true, true);
                }

                return;
            }
            else
                printf("duplicateeed :(\n");
        }
    }
    if (!hasAttacker && similarInterest && ShouldSuppressIncomingInterest (inFace, interest, pitEntry) && !interestServed)
    {
        // printf("supressed :(\n");
        pitEntry->AddIncoming (inFace/*, interest->GetInterestLifetime ()*/);
        // update PIT entry lifetime
        pitEntry->UpdateLifetime (interest->GetInterestLifetime ());

        // Suppress this interest if we're still expecting data from some other face
        NS_LOG_DEBUG ("Suppress interests");

        m_dropInterests (interest, inFace);

        DidSuppressSimilarInterest (inFace, interest, pitEntry);

        return;
    }

    PropagateInterest (inFace, interest, pitEntry);

    pitUsageTrace(getPitUsage(), pit->GetSize());
}

void MonitorAwareRouting::WillSatisfyPendingInterest (Ptr<Face> inFace, Ptr<pit::Entry> pitEntry)
{
    super::WillSatisfyPendingInterest(inFace, pitEntry);

    if(recordStats())
    {
        Name name = pitEntry->GetPrefix();
        Name prefix = name.getSubName(0, 1);

        satisfiedNames.insert(name);

        entriesSatisfiedBeforeTrace(satisfiedNames.size());

        // Increase the counters according to the number of incoming faces of the PIT entry
        BOOST_FOREACH(const pit::IncomingFace &face, pitEntry->GetIncoming())
        {
            satisfiedPerFace[face.m_face]++;

            std::set<Ptr<pit::Entry> >::iterator monitoredFirst = locallyMonitored[face.m_face].find(pitEntry);
            if(monitoredFirst != locallyMonitored[face.m_face].end())
            {
                // The interest on this interface has been monitored by this node first
                locallyMonitored[face.m_face].erase(monitoredFirst);
                satisfiedUnmonitored++;
                satisfiedUnmonitoredPerFace[face.m_face]++;
                satisfiedUnmonitoredPerFacePerName[face.m_face][prefix]++;
            }

        }
    }
}

void MonitorAwareRouting::PropagateInterest (Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry)
{
    bool isRetransmitted = m_detectRetransmissions && // a small guard
        DetectRetransmittedInterest (inFace, interest, pitEntry);

    bool isServed = interest->GetServed() == 1;

    if(!isServed)
        // Don't add interface to PIT entry when the interest has already been served. An already
        // served interest is only forwarded to be monitored.
        pitEntry->AddIncoming (inFace/*, interest->GetInterestLifetime ()*/);

    /// @todo Make lifetime per incoming interface
    pitEntry->UpdateLifetime (interest->GetInterestLifetime ());

    bool propagated = DoPropagateInterest (inFace, interest, pitEntry);

    if (!propagated && isRetransmitted) //give another chance if retransmitted
    {
        // increase max number of allowed retransmissions
        pitEntry->IncreaseAllowedRetxCount ();

        // try again
        propagated = DoPropagateInterest (inFace, interest, pitEntry);
    }

    // ForwardingStrategy will try its best to forward packet to at least one interface.
    // If no interests was propagated, then there is not other option for forwarding or
    // ForwardingStrategy failed to find it.
    if (!propagated && pitEntry->AreAllOutgoingInVain ())
    {
        DidExhaustForwardingOptions (inFace, interest, pitEntry);
    }
}

bool MonitorAwareRouting::DoPropagateInterest (Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry)
{
    NS_LOG_FUNCTION (this);
    
    // Ptr<NetDevice> netDevice = NULL;
    // if(DynamicCast<NetDeviceFace>(inFace))
    // {
    //     if(DynamicCast<PointToPointNetDevice>(DynamicCast<NetDeviceFace>(inFace)->GetNetDevice()))
    //     {
    //         netDevice = DynamicCast<NetDeviceFace>(inFace)->GetNetDevice();
    //         int id1 = (DynamicCast<PointToPointNetDevice> (netDevice)->GetChannel ())->GetDevice (0)->GetNode ()->GetId ();
    //         int id2 = (DynamicCast<PointToPointNetDevice> (netDevice)->GetChannel ())->GetDevice (1)->GetNode ()->GetId ();
    //         int id = id1 == inFace->GetNode()->GetId()?id2:id1;
            
    //         RequestedContentInterface(inFace->GetId(), interest->GetName());
    //     }
    // }

    switch(m_mode)
    {
        case MAR1:
            return DoPropagateInterestMAR1(inFace, interest, pitEntry);
        case MAR2:
            return DoPropagateInterestMAR2(inFace, interest, pitEntry);
        case MAR3:
            return DoPropagateInterestMAR3(inFace, interest, pitEntry);
        default:
            // opportunistic is "best route"
            return DoPropagateInterestBestRoute(inFace, interest, pitEntry);
    }
}

bool MonitorAwareRouting::DoPropagateInterestBestRoute (Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry)
{
  NS_LOG_FUNCTION (this << interest->GetName ());

  int propagatedCount = 0;

  BOOST_FOREACH (const fib::FaceMetric &metricFace, pitEntry->GetFibEntry ()->m_faces.get<fib::i_metric> ())
    {
      NS_LOG_DEBUG ("Trying " << boost::cref(metricFace));
      if (metricFace.GetStatus () == fib::FaceMetric::NDN_FIB_RED) // all non-read faces are in front
        break;

      if (!TrySendOutInterest (inFace, metricFace.GetFace (), interest, pitEntry))
        {
          continue;
        }

      propagatedCount++;
      break; // do only once
    }

  NS_LOG_INFO ("Propagated to " << propagatedCount << " faces");
  return propagatedCount > 0;
}


bool MonitorAwareRouting::DoPropagateInterestOpportunistic(Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry)
{
    NS_LOG_FUNCTION (this);

     bool interestServed = interest->GetServed() != 0;
     bool interestMonitored = interest->GetMonitored() != 0;

     if(interestServed && interestMonitored)
         return true;

     if(!interestMonitored && hasMonitor)
     {
         // Force forward to local monitor
         NS_LOG_INFO("Forward to " << boost::cref(*localMonitorFace));
         return TrySendOutInterest(inFace, localMonitorFace, interest, pitEntry);
     }

     if(!interestServed || !interestMonitored){
         BOOST_FOREACH (const fib::FaceMetric &metricFace, pitEntry->GetFibEntry ()->m_faces.get<fib::i_metric> ())
         {
             if (metricFace.GetStatus () == fib::FaceMetric::NDN_FIB_RED) // all non-read faces are in front
             {
                 break;
             }

             if (metricFace.GetFace()->GetFlags() == MonitorApp::FLAG && interestMonitored)
             {
                 // Skip monitor apps (they have been handled above)
                 continue;
             }

             if (metricFace.GetFace()->GetFlags() == 1 && interestServed)
             {
                 // Skip server apps if already served
                 continue;
             }

             NS_LOG_DEBUG ("Trying " << boost::cref(metricFace));
             if (!TrySendOutInterest (inFace, metricFace.GetFace (), interest, pitEntry))
             {
                 continue;
             }

             return true;
         }
     }

     int propagatedCount = 0;
     // FTMB
     if(m_ftbm && propagatedCount < 1 && !interestMonitored)
     {
         // Forward to nearest monitor node
         Ptr<fib::Entry> entry = m_fib->Find(monitorPrefix);
         Ptr<Face> face = entry->FindBestCandidate(0).GetFace();

         if(TrySendOutInterest (inFace, entry->FindBestCandidate(0).GetFace(), interest, pitEntry))
         {
             std::stringbuf str;
             std::ostream stream(&str);
             face->Print(stream);

             NS_LOG_DEBUG("Not monitored yet, forward to nearest monitor node via " << str.str());
             propagatedCount++;
         }
     }

     NS_LOG_INFO ("Propagated to " << propagatedCount << " net-faces");
     return propagatedCount > 0;
}

bool MonitorAwareRouting::DoPropagateInterestMAR1(Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry)
{
    NS_LOG_FUNCTION (this);
    bool interestMonitored = interest->GetMonitored() != 0;

    if(!interestMonitored)
    {
        // Strictly forward towards monitor

        if(nearestMonitorFace == NULL)
        {

            if(hasMonitor && content_monitorID.find(interest->GetName()) != content_monitorID.end())
            {

                std::string forwardPrefix = "/monitor/" + boost::lexical_cast<std::string>(content_monitorID[interest->GetName()]);
                Ptr<fib::Entry> entry = m_fib->Find(forwardPrefix);
                nearestMonitorFace = entry->FindBestCandidate(0).GetFace();
            }
            else
            {
                if(hasMonitor)
                {
                    nearestMonitorFace = localMonitorFace;
                }
                else
                {
                    Ptr<fib::Entry> entry = m_fib->Find(monitorPrefix);
                    nearestMonitorFace = entry->FindBestCandidate(0).GetFace();
                }
            }
            
        }

        if(TrySendOutInterest (inFace, nearestMonitorFace, interest, pitEntry))
        {
            if(g_log.IsEnabled(ns3::LOG_LEVEL_DEBUG))
            {
                std::stringbuf str;
                std::ostream stream(&str);
                nearestMonitorFace->Print(stream);
                NS_LOG_DEBUG("Not monitored yet, forward to nearest monitor node via " << str.str());
            }
        }

        return true;

    }
    else
    {
        return DoPropagateInterestOpportunistic(inFace, interest, pitEntry);
    }
}

bool MonitorAwareRouting::DoPropagateInterestMAR2(Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry)
{
    NS_LOG_FUNCTION (this);
    bool interestMonitored = interest->GetMonitored() != 0;

    if(!interestMonitored && !hasMonitor)
    {
        Name prefix = interest->GetName().getSubName(0, interest->GetName().size() - 1);
        Ptr<Face> forwardVia;

        if(routingTableMAR2[prefix] != NULL)
        {
            // We already have calculated the best route to the given prefix
            forwardVia = routingTableMAR2[prefix];
        }
        else
        {
            // We have to calculate the best route

            int currentMinCost = INT_MAX;

            for (Ptr<fib::Entry> entry = m_fib->Begin (); entry != m_fib->End (); entry = m_fib->Next (entry))
            {
                if(entry->GetPrefix().size() < 2 || entry->GetPrefix().getSubName(0, 1) != monitorPrefix)
                {
                    // Skip faces whose prefix has only 1 component (eg. "monitor"). We only want
                    // something like "monitor/2" here.
                    continue;
                }

                BOOST_FOREACH (const fib::FaceMetric &metricFace, entry->m_faces.get<fib::i_metric> ())
                {
                    // The FIB entries to the different monitors have the prefixes monitor/1, monitor/2,
                    // etc. In the global routing we can only query by the id, e.g. 1 or 2. Thus we
                    // extract the last part of the FIB entry here
                    int monitorId = atoi(entry->GetPrefix().get(1).toUri().c_str());

                    int costMeToMonitor = metricFace.GetRoutingCost();
                    int costMonitorToServer = GlobalRoutingInfo::get(monitorId, prefix);
                    int cost = costMeToMonitor + costMonitorToServer;

                    NS_LOG_DEBUG("Could forward via " << entry->GetPrefix() << " for " << cost);

                    if(cost < currentMinCost)
                    {
                        currentMinCost = cost;
                        forwardVia = metricFace.GetFace();
                    }
                }
            }

            routingTableMAR2[prefix] = forwardVia;
        }

        NS_LOG_INFO("Forward to " << boost::cref(*forwardVia));
        return TrySendOutInterest(inFace, forwardVia, interest, pitEntry);

    }
    else
    {
        return DoPropagateInterestOpportunistic(inFace, interest, pitEntry);
    }

}

bool MonitorAwareRouting::DoPropagateInterestMAR3(Ptr<Face> inFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry)
{
    return false;
}

bool MonitorAwareRouting::TrySendOutInterest (Ptr<Face> inFace, Ptr<Face> outFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry)
{
    if (!CanSendOutInterest (inFace, outFace, interest, pitEntry))
    {
        return false;
    }

    bool isServed = interest->GetServed() == 1;

    if(!isServed)
    {
        // Don't add interface to PIT entry when the interest has already been served. An already
        // served interest is only forwarded to be monitored.
        pitEntry->AddOutgoing (outFace);
    }
    else if(pitEntry->GetIncoming().size() == 0 && pitEntry->GetOutgoing().size() == 0)
    {
        m_pit->MarkErased(pitEntry);
    }

    //transmission
    bool successSend = outFace->SendInterest (interest);
    if (!successSend)
    {
        m_dropInterests (interest, outFace);
    }

    DidSendOutInterest (inFace, outFace, interest, pitEntry);

    return true;
}

void MonitorAwareRouting::DidSendOutInterest(Ptr<Face> inFace, Ptr<Face> outFace, Ptr<const Interest> interest, Ptr<pit::Entry> pitEntry)
{
    super::DidSendOutInterest(inFace, outFace, interest, pitEntry);
}

void MonitorAwareRouting::WillEraseTimedOutPendingInterest (Ptr<pit::Entry> pitEntry)
{
    super::WillEraseTimedOutPendingInterest(pitEntry);

    if(recordStats())
    {
        Name prefix = pitEntry->GetPrefix().getSubName(0, 1);
        BOOST_FOREACH(const pit::IncomingFace &face, pitEntry->GetIncoming())
        {
            // Count the timeout for every interface the interest has been received on
            timedOutPerFace[face.m_face]++;

            std::set<Ptr<pit::Entry> >::iterator monitoredFirst = locallyMonitored[face.m_face].find(pitEntry);
            if(monitoredFirst != locallyMonitored[face.m_face].end())
            {
                // The interest on this interface has been monitored by this node first

                locallyMonitored[face.m_face].erase(monitoredFirst);
                timedOutUnmonitored++;
                timedOutUnmonitoredPerName[prefix]++;
                timedOutUnmonitoredPerFace[face.m_face]++;
                timedOutUnmonitoredPerFacePerName[face.m_face][prefix]++;

                // if(timedOutPrefixesPerFace[face.m_face].find(prefix) == timedOutPrefixesPerFace[face.m_face].end())
                // {
                //     std::cout << "Identified: " << prefix << " @ " << getSatisfactionRatioUnmonitored(face.m_face, prefix)
                //         << " satU=" << satisfiedUnmonitoredPerFacePerName[face.m_face][prefix]
                //         << " timU=" << timedOutUnmonitoredPerFacePerName[face.m_face][prefix]
                //         << " sat=" << satisfiedPerFace[face.m_face]
                //         << " tim=" << timedOutPerFace[face.m_face]
                //         << std::endl;
                //     NS_LOG_DEBUG("Identified: " << prefix << " @ " << getSatisfactionRatioUnmonitored(face.m_face, prefix)
                //         << " satU=" << satisfiedUnmonitoredPerFacePerName[face.m_face][prefix]
                //         << " timU=" << timedOutUnmonitoredPerFacePerName[face.m_face][prefix]
                //         << " sat=" << satisfiedPerFace[face.m_face]
                //         << " tim=" << timedOutPerFace[face.m_face]);
                // }

                // Identify the prefix as "malicious"
                timedOutPrefixesPerFace[face.m_face].insert(prefix);
                timedOutPrefixes.insert(prefix);
            }

        }

    }
}

double MonitorAwareRouting::getSatisfactionRatioUnmonitored(Ptr<Face> inFace, Name name)
{
    double result;

    if(timedOutUnmonitoredPerFacePerName[inFace][name] == 0 && satisfiedUnmonitoredPerFacePerName[inFace][name] == 0)
        result = 1;
    else
        result = (double) satisfiedUnmonitoredPerFacePerName[inFace][name] / (timedOutUnmonitoredPerFacePerName[inFace][name] + satisfiedUnmonitoredPerFacePerName[inFace][name]);

    return result;
}

double MonitorAwareRouting::getPitUsage()
{
    // If the PIT size is not restricted return -1
    return pitMaxSize == 0 ? -1 : (double)pit->GetSize() / (double)pitMaxSize;
}

uint32_t MonitorAwareRouting::getUnmonitoredSatisfied()
{
    return satisfiedUnmonitored;
}

uint32_t MonitorAwareRouting::getUnmonitoredTimedOut()
{
    return timedOutUnmonitored;
}

uint32_t MonitorAwareRouting::getPitEntries()
{
    return pit->GetSize();
}

MonitorAwareRouting::PerNameCounter MonitorAwareRouting::getEntriesPerNameUnmonitored()
{
    MonitorAwareRouting::PerNameCounter result;

    // Get the number of PIT entries that have been monitored first by this node
    std::pair<Ptr<Face>, std::set<Ptr<pit::Entry> > > pair;

    std::set<Ptr<pit::Entry> > entries;
    std::map<Name, std::set<Ptr<pit::Entry> > > entriesPerName;

    BOOST_FOREACH(pair, locallyMonitored)
    {
        entries.insert(pair.second.begin(), pair.second.end());

        BOOST_FOREACH(const Ptr<pit::Entry> e, pair.second)
        {
            Name prefix = e->GetPrefix().getSubName(0, 1);
            if(timedOutPrefixes.find(prefix) != timedOutPrefixes.end())
                entriesPerName[prefix].insert(e);
        }
    }

    std::pair<Name, std::set<Ptr<pit::Entry> > > entry;
    BOOST_FOREACH(entry, entriesPerName)
    {
        result[entry.first] = entry.second.size();
    }

    return result;
}

MonitorAwareRouting::PerNameCounter MonitorAwareRouting::getTimedOutEntriesPerNameUnmonitored()
{
    return timedOutUnmonitoredPerName;
}

void MonitorAwareRouting::resetStats()
{
    if(!recordStats())
        return;

    // Keep satisfiedNames for 10 observation periods
    if(resetRound == 9)
    {
        satisfiedNames.clear();
        resetRound = 0;
    }
    else
    {
        resetRound++;
    }

    timedOutPrefixesPerFace.clear();
    timedOutPrefixes.clear();
    requestedNames.clear();

    timedOutUnmonitored = 0;
    satisfiedUnmonitored = 0;

    satisfiedPerFace.clear();
    timedOutPerFace.clear();

    satisfiedUnmonitoredPerFace.clear();
    timedOutUnmonitoredPerFace.clear();

    satisfiedUnmonitoredPerFacePerName.clear();
    timedOutUnmonitoredPerFacePerName.clear();

    satisfiedUnmonitoredPerName.clear();
    timedOutUnmonitoredPerName.clear();
}

bool MonitorAwareRouting::recordStats()
{
    return (detection >= 1 && detection <= 2) || hasMonitor;
}

/*
 * This is used by the CC to report malicious prefixes to the CNMRs.
 */
void MonitorAwareRouting::setMaliciousPrefixes(std::set<Name> prefixes)
{
    maliciousPrefixes = prefixes;
}

bool MonitorAwareRouting::getHasMonitor()
{
    return hasMonitor;
}

void MonitorAwareRouting::setHasClient()
{
    hasClient = true;
}

void MonitorAwareRouting::setHasServer()
{
    hasServer = true;
}
//////////////////////////////////////////////////
////////////////////MY STUFF//////////////////////
//////////////////////////////////////////////////


void MonitorAwareRouting::setNotForCache(std::set<Name> _not_for_cache)
{
    not_for_cache = _not_for_cache;
}
void MonitorAwareRouting::setContentMonitorID(std::map<Name,uint32_t> _content_monitorID)
{
    content_monitorID = _content_monitorID;
}


} // namespace fw
} // namespace ndn
} // namespace ns3
