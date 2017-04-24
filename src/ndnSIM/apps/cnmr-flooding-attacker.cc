#include "ndn-consumer.h"
#include "cnmr-flooding-attacker.h"
#include "ns3/ptr.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/packet.h"
#include "ns3/callback.h"
#include "ns3/string.h"
#include "ns3/boolean.h"
#include "ns3/uinteger.h"
#include "ns3/integer.h"
#include "ns3/double.h"

#include "ns3/ndn-l3-protocol.h"
#include "ns3/ndn-app-face.h"
#include "ns3/ndn-interest.h"
#include "ns3/ndn-data.h"
#include "ns3/ndn-pit.h"

#include "ns3/ndnSIM/utils/ndn-fw-hop-count-tag.h"

NS_LOG_COMPONENT_DEFINE ("CnmrFloodingAttacker");

namespace ns3 {
namespace ndn {

NS_OBJECT_ENSURE_REGISTERED (CnmrFloodingAttacker);

TypeId CnmrFloodingAttacker::GetTypeId (void)
{
    static TypeId tid = TypeId ("ns3::ndn::CnmrFloodingAttacker")
        .SetGroupName ("Ndn")
        .SetParent<App> ()
        .AddConstructor<CnmrFloodingAttacker> ()

        .AddAttribute ("Frequency", "Frequency of interest packets",
                StringValue ("1.0"),
                MakeDoubleAccessor (&CnmrFloodingAttacker::m_frequency),
                MakeDoubleChecker<double> ())

        .AddAttribute ("Prefix","Name of the Interest",
                StringValue ("/"),
                MakeNameAccessor (&CnmrFloodingAttacker::m_interestName),
                MakeNameChecker ())

        .AddAttribute ("LifeTime", "LifeTime for interest packet",
                StringValue ("2s"),
                MakeTimeAccessor (&CnmrFloodingAttacker::m_interestLifeTime),
                MakeTimeChecker ())

        .AddAttribute ("MinSeq",
                "Minimum sequence number to request",
                IntegerValue (1024),
                MakeIntegerAccessor (&CnmrFloodingAttacker::m_seqMin),
                MakeIntegerChecker<uint32_t> ())

        .AddAttribute ("StartAt",
                "When to start the attack. Attackers do nothing before.",
                TimeValue (Minutes (10)),
                MakeTimeAccessor (&CnmrFloodingAttacker::m_startAt),
                MakeTimeChecker ())

        .AddAttribute ("StopAt",
                "When to stop the attack. Attackers do nothing after.",
                TimeValue (Minutes (20)),
                MakeTimeAccessor (&CnmrFloodingAttacker::m_stopAt),
                MakeTimeChecker ())
        ;
    return tid;
}

CnmrFloodingAttacker::CnmrFloodingAttacker()
{}

void CnmrFloodingAttacker::StartApplication()
{
    // INLINED ndn::App::StartApplication ();
    NS_LOG_FUNCTION_NOARGS ();

    NS_ASSERT (m_active != true);
    m_active = true;

    NS_ASSERT_MSG (GetNode ()->GetObject<L3Protocol> () != 0,
            "Ndn stack should be installed on the node " << GetNode ());

    // step 1. Create a face
    m_face = CreateObject<AppFace> (/*Ptr<App> (this)*/this);

    // ---------------------------------------------------------------------------------------------------
    // CHANGE JULIAN: Set this flag to be able to identify the face of this app in the forwarding strategy
    m_face->SetFlags(FLAG);
    // END CHANGE
    // ---------------------------------------------------------------------------------------------------

    // step 2. Add face to the Ndn stack
    GetNode ()->GetObject<L3Protocol> ()->AddFace (m_face);

    // step 3. Enable face
    m_face->SetUp (true);
    // END INLINED ndn::App::StartApplication ();

    m_randNonce = UniformVariable (0, std::numeric_limits<uint32_t>::max ());
    m_randomSeqId = UniformVariable (m_seqMin + 1, std::numeric_limits<uint32_t>::max ());
    m_randomTime = UniformVariable (0.0, 2 * 1.0 / m_frequency);
    Simulator::Schedule (m_startAt, &CnmrFloodingAttacker::ScheduleNextPacket, this);
}

void CnmrFloodingAttacker::StopApplication () // Called at time specified by Stop
{
  NS_LOG_FUNCTION_NOARGS ();

  // cancel periodic packet generation
  Simulator::Cancel (m_sendEvent);

  // cleanup base stuff
  App::StopApplication ();
}

void CnmrFloodingAttacker::ScheduleNextPacket()
{
    if(!m_sendEvent.IsRunning())
        m_sendEvent = Simulator::Schedule (Seconds(m_randomTime.GetValue()), &CnmrFloodingAttacker::SendPacket, this);
}

void CnmrFloodingAttacker::SendPacket ()
{
    NS_LOG_FUNCTION (this);

    uint32_t seq = GetNextSeq();

    Ptr<Name> nameWithSequence = Create<Name> (m_interestName);
    nameWithSequence->appendSeqNum (seq);

    Ptr<Interest> interest = Create<Interest> ();
    interest->SetNonce               (m_randNonce.GetValue ());
    interest->SetName                (nameWithSequence);
    interest->SetInterestLifetime    (m_interestLifeTime);

    NS_LOG_INFO ("Requesting Interest: " << *interest);

    FwHopCountTag hopCountTag;
    hopCountTag.Add(GetNode()->GetId());
    interest->GetPayload ()->AddPacketTag (hopCountTag);

    m_transmittedInterests (interest, this, m_face);
    m_face->ReceiveInterest (interest);

    if(Simulator::Now() >= m_stopAt)
    {
        m_active = false;
    }
    else
    {
        ScheduleNextPacket();
    }
}

uint32_t CnmrFloodingAttacker::GetNextSeq()
{
    return m_randomSeqId.GetValue();
}

} // namespace ndn
} // namespace ns3
