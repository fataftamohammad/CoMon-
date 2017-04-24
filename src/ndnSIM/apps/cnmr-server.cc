#include "cnmr-server.h"
#include "ns3/log.h"
#include "ns3/ndn-interest.h"
#include "ns3/ndn-data.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"

#include "ns3/ndn-app-face.h"
#include "ns3/ndn-fib.h"

#include "ns3/ndnSIM/utils/ndn-fw-hop-count-tag.h"

#include <boost/ref.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/lambda/bind.hpp>
namespace ll = boost::lambda;

NS_LOG_COMPONENT_DEFINE ("CnmrServer");

namespace ns3 {
namespace ndn {

NS_OBJECT_ENSURE_REGISTERED (CnmrServer);

TypeId CnmrServer::GetTypeId (void)
{
    static TypeId tid = TypeId ("ns3::ndn::CnmrServer")
        .SetGroupName ("Ndn")
        .SetParent<App> ()
        .AddConstructor<CnmrServer> ()

        .AddTraceSource ("InterestConsumed",  "InterestConsumed",  MakeTraceSourceAccessor (&CnmrServer::interestConsumedTrace))

        .AddAttribute ("Prefix","Prefix, for which server has the data",
                       StringValue ("/"),
                       MakeNameAccessor (&CnmrServer::m_prefix),
                       MakeNameChecker ())
        .AddAttribute ("PayloadSize", "Virtual payload size for Content packets",
                       UintegerValue (1024),
                       MakeUintegerAccessor (&CnmrServer::m_virtualPayloadSize),
                       MakeUintegerChecker<uint32_t> ())
        .AddAttribute ("ContentItems", "Number of content items [0-n]",
                       UintegerValue (1024),
                       MakeUintegerAccessor (&CnmrServer::m_numContent),
                       MakeUintegerChecker<uint32_t> ())
    ;
    return tid;
}

CnmrServer::CnmrServer ()
{
}

void CnmrServer::StartApplication ()
{
    NS_LOG_FUNCTION_NOARGS ();
    App::StartApplication ();

    Ptr<Fib> fib = GetNode ()->GetObject<Fib> ();
    Ptr<fib::Entry> fibEntry = fib->Add (m_prefix, m_face, 0);
    fibEntry->UpdateStatus (m_face, fib::FaceMetric::NDN_FIB_GREEN);
}

void CnmrServer::StopApplication ()
{
    NS_LOG_FUNCTION_NOARGS ();
    App::StopApplication ();
}


void CnmrServer::OnInterest (Ptr<const Interest> interest)
{
    App::OnInterest (interest); // tracing inside

    if (!m_active) return;

    uint64_t seqNum = interest->GetName().get(interest->GetName().size() - 1).toSeqNum();
    bool didServe = false;
    // A server only has data with sequence numbers < m_numContent.  Only serve those requests!
    bool legitimateRequest = seqNum < m_numContent;

    FwHopCountTag hopCountTag;
    interest->GetPayload ()->PeekPacketTag (hopCountTag);

    if(legitimateRequest)
    {
        didServe = true;

        Ptr<Data> data = Create<Data> (Create<Packet> (m_virtualPayloadSize));
        Ptr<Name> dataName = Create<Name> (interest->GetName ());
        dataName->append (m_postfix);
        data->SetName (dataName);
        data->SetFreshness (m_freshness);
        data->SetTimestamp (Simulator::Now());

        data->SetSignature (m_signature);
        if (m_keyLocator.size () > 0)
        {
            data->SetKeyLocator (Create<Name> (m_keyLocator));
        }

        // Echo back FwHopCountTag
        data->GetPayload ()->AddPacketTag (hopCountTag);

        NS_LOG_INFO("Responding to interest (took " << hopCountTag.Get() << " hops) with Data: " << data->GetName ());

        m_face->ReceiveData (data);
        m_transmittedDatas (data, this, m_face);
    }
    else
    {
        NS_LOG_INFO("Cannot respond to  interest (" << hopCountTag.Get() << " hops) with seq=: " << interest->GetName());
    }

    // (Possible) forward the interest if it has not yet been monitored. The interest is only
    // forwarded to another if if FTBM is enabled. The MonitorAwareRouting takes care of this.
    if(interest->GetMonitored() == 0)
    {
        // NS_LOG_DEBUG("Served interest but it's not monitored. Forwarding...");

        Ptr<Name> nameWithSequence = Create<Name> (interest->GetName ());

        Ptr<Interest> newInterest = Create<Interest> ();
        newInterest->SetNonce (interest->GetNonce ());
        newInterest->SetName (interest->GetName ());
        newInterest->SetInterestLifetime (interest->GetInterestLifetime ());

        if(didServe)
        {
            newInterest->SetServed(1);
        }

        newInterest->GetPayload()->AddPacketTag(hopCountTag);

        m_face->ReceiveInterest (newInterest);
    }
    else// if(didServe)
    {
        // If the interest has been monitored before, and served by this node, it is not forwarded
        // any further -> print the hops (but don't add self to hop list becase the interest leaves
        // the AS at this point).
        interestConsumedTrace(interest, false, legitimateRequest);
    }
}

} // namespace ndn
} // namespace ns3
