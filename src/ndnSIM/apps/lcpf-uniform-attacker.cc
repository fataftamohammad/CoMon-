#include "ndn-consumer.h"
#include "lcpf-uniform-attacker.h"
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

#include <boost/algorithm/string.hpp>
#include <fstream>
#include "ns3/ndnSIM/utils/ndn-fw-hop-count-tag.h"

NS_LOG_COMPONENT_DEFINE ("LcpfUniformAttacker");

namespace ns3 {
namespace ndn {

NS_OBJECT_ENSURE_REGISTERED (LcpfUniformAttacker);

TypeId LcpfUniformAttacker::GetTypeId (void)
{
    static TypeId tid = TypeId ("ns3::ndn::LcpfUniformAttacker")
        .SetGroupName ("Ndn")
        .SetParent<App> ()
        .AddConstructor<LcpfUniformAttacker> ()

        .AddAttribute ("Frequency", "Frequency of interest packets",
                StringValue ("1.0"),
                MakeDoubleAccessor (&LcpfUniformAttacker::m_frequency),
                MakeDoubleChecker<double> ())

        .AddAttribute ("LifeTime", "LifeTime for interest packet",
                StringValue ("3s"),
                MakeTimeAccessor (&LcpfUniformAttacker::m_interestLifeTime),
                MakeTimeChecker ())

        .AddAttribute ("Prefixes", "Comma-seperated string of prefixes this client can request",
                StringValue ("/google.com,"),
                MakeStringAccessor (&LcpfUniformAttacker::m_p),
                MakeStringChecker ())

        .AddAttribute("NumberOfContents", "Number of the Contents in total", StringValue("3000"),
                MakeUintegerAccessor(&LcpfUniformAttacker::SetNumberOfContents,
                                     &LcpfUniformAttacker::GetNumberOfContents),
                MakeUintegerChecker<uint32_t>())

        .AddAttribute ("RelativeSetSize",
                "UniformAttacker relative requestsed set size",
                DoubleValue (0),
                MakeDoubleAccessor (&LcpfUniformAttacker::m_relativeSetSize),
                MakeDoubleChecker<double> ())

        .AddAttribute ("StartAt",
                "When to start the attack. LcpfUniformAttackers do nothing before.",
                TimeValue (Minutes (10)),
                MakeTimeAccessor (&LcpfUniformAttacker::m_startAt),
                MakeTimeChecker ())

        .AddAttribute ("StopAt",
                "When to stop the attack. LcpfUniformAttackers do nothing after.",
                TimeValue (Minutes (20)),
                MakeTimeAccessor (&LcpfUniformAttacker::m_stopAt),
                MakeTimeChecker ())
        ;
    return tid;
}

LcpfUniformAttacker::LcpfUniformAttacker()
{}

void LcpfUniformAttacker::StartApplication()
{
    NS_LOG_FUNCTION_NOARGS();

    SetPrefixes(m_p);
    
    // do base stuff
    App::StartApplication();

    m_randNonce = UniformVariable (0, std::numeric_limits<uint32_t>::max ());
    m_randomSeqId = UniformVariable (m_numberOfContents - ( m_numberOfContents * m_relativeSetSize ) , m_numberOfContents);
    m_randomTime = UniformVariable (0.0, 2 * 1.0 / m_frequency);

    Simulator::Schedule (m_startAt, &LcpfUniformAttacker::ScheduleNextPacket, this);
}

void LcpfUniformAttacker::StopApplication () // Called at time specified by Stop
{
  NS_LOG_FUNCTION_NOARGS ();

  // cancel periodic packet generation
  Simulator::Cancel (m_sendEvent);

  // cleanup base stuff
  App::StopApplication ();
}

void LcpfUniformAttacker::ScheduleNextPacket()
{
    if(!m_sendEvent.IsRunning())
        m_sendEvent = Simulator::Schedule (Seconds(m_randomTime.GetValue()), &LcpfUniformAttacker::SendPacket, this);
}

void LcpfUniformAttacker::SendPacket ()
{
    NS_LOG_FUNCTION (this);

    uint32_t seq = GetNextSeq();

    Ptr<Name> nameWithSequence = Create<Name> (GetNextPrefix(seq%prefixes.size()));
    nameWithSequence->appendSeqNum (seq/prefixes.size());

    Ptr<Interest> interest = Create<Interest> ();
    interest->SetNonce               (m_randNonce.GetValue ());
    interest->SetName                (nameWithSequence);
    interest->SetInterestLifetime    (m_interestLifeTime);

    NS_LOG_INFO ("Requesting Interest: " << *interest);

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

uint32_t LcpfUniformAttacker::GetNextSeq()
{
    return m_randomSeqId.GetValue();
}

void
LcpfUniformAttacker::SetNumberOfContents(uint32_t numOfContents)
{
  m_numberOfContents = numOfContents;
}

uint32_t
LcpfUniformAttacker::GetNumberOfContents() const
{
  return m_numberOfContents;
}
void LcpfUniformAttacker::SetPrefixes(std::string strPrefixes)
{
    std::vector<std::string> strs;
    boost::split(strs, strPrefixes, boost::is_any_of(","));
    prefixes.clear();
    for(size_t i = 0; i < strs.size(); i++)
    {
        prefixes.push_back(Name(strs[i]));
    }

}

Name &LcpfUniformAttacker::GetNextPrefix(uint32_t a)
{
    return prefixes[a];
}

} // namespace ndn
} // namespace ns3
