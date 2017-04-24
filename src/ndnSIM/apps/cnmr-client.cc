#include "ndn-consumer.h"
#include "cnmr-client.h"
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

#include "ns3/ndn-app-face.h"
#include "ns3/ndn-interest.h"
#include "ns3/ndn-data.h"

#include "ns3/ndnSIM/utils/ndn-fw-hop-count-tag.h"

#include <boost/algorithm/string.hpp>

NS_LOG_COMPONENT_DEFINE ("CnmrClient");

namespace ns3 {
namespace ndn {

NS_OBJECT_ENSURE_REGISTERED (CnmrClient);

TypeId CnmrClient::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::ndn::CnmrClient")
    .SetGroupName ("Ndn")
    .SetParent<Consumer> ()
    .AddConstructor<CnmrClient> ()

    .AddAttribute ("Frequency", "Frequency of interest packets",
                   StringValue ("1.0"),
                   MakeDoubleAccessor (&CnmrClient::m_frequency),
                   MakeDoubleChecker<double> ())

    .AddAttribute ("Prefixes", "Comma-seperated string of prefixes this client can request",
                   StringValue ("google.com,"),
                   MakeStringAccessor (&CnmrClient::SetPrefixes),
                   MakeStringChecker ())

    .AddAttribute ("NumberOfContents", "Number of the Contents in total",
                   StringValue ("1024"),
                   MakeUintegerAccessor (&CnmrClient::SetNumberOfContents, &CnmrClient::GetNumberOfContents),
                   MakeUintegerChecker<uint32_t> ())

    .AddAttribute ("q", "parameter of improve rank",
                   StringValue ("0.7"),
                   MakeDoubleAccessor (&CnmrClient::SetQ, &CnmrClient::GetQ),
                   MakeDoubleChecker<double> ())

    .AddAttribute ("s", "parameter of power",
                   StringValue ("0.7"),
                   MakeDoubleAccessor (&CnmrClient::SetS, &CnmrClient::GetS),
                   MakeDoubleChecker<double> ())
    ;

  return tid;
}

CnmrClient::CnmrClient()
{
}

void CnmrClient::StartApplication()
{
    NS_LOG_FUNCTION_NOARGS ();
    App::StartApplication ();

    m_random = new UniformVariable (0.0, 2 * 1.0 / m_frequency);
    ScheduleNextPacket();
}

void CnmrClient::SetPrefixes(std::string strPrefixes)
{
    std::vector<std::string> strs;
    boost::split(strs, strPrefixes, boost::is_any_of(","));
    prefixes.clear();

    for(size_t i = 0; i < strs.size(); i++)
    {
        prefixes.push_back(Name(strs[i]));
    }

    rngPrefix = new UniformVariable (0, strs.size());
}

Name &CnmrClient::GetNextPrefix()
{
    return prefixes[rngPrefix->GetInteger()];
}

void CnmrClient::ScheduleNextPacket ()
{
    if(!m_sendEvent.IsRunning())
        m_sendEvent = Simulator::Schedule (Seconds(m_random->GetValue ()), &CnmrClient::SendPacket, this);
}

void CnmrClient::SendPacket ()
{
    if (!m_active) return;

    uint32_t seq = GetNextSeq();

    Ptr<Name> nameWithSequence = Create<Name> (GetNextPrefix());
    nameWithSequence->appendSeqNum (seq);

    Ptr<Interest> interest = Create<Interest> ();
    interest->SetNonce               (m_rand.GetValue ());
    interest->SetName                (nameWithSequence);
    interest->SetInterestLifetime    (m_interestLifeTime);

    NS_LOG_INFO ("Requesting Interest: " << *interest);

    WillSendOutInterest (seq);

    FwHopCountTag hopCountTag;
    interest->GetPayload ()->AddPacketTag (hopCountTag);

    m_transmittedInterests (interest, this, m_face);
    m_face->ReceiveInterest (interest);

    ScheduleNextPacket();
}

uint32_t CnmrClient::GetNextSeq()
{
    uint32_t content_index = 1; //[1, m_N]
    double p_sum = 0;

    double p_random = m_SeqRng.GetValue();
    while (p_random == 0)
    {
        p_random = m_SeqRng.GetValue();
    }
    // NS_LOG_LOGIC("p_random="<<p_random);
    for (uint32_t i=1; i<=m_N; i++)
    {
        p_sum = m_Pcum[i];   //m_Pcum[i] = m_Pcum[i-1] + p[i], p[0] = 0;   e.g.: p_cum[1] = p[1], p_cum[2] = p[1] + p[2]
        if (p_random <= p_sum)
        {
            content_index = i;
            break;
        }
    }
    // NS_LOG_DEBUG("RandomNumber="<<content_index);
    return content_index;
}

void CnmrClient::SetNumberOfContents (uint32_t numOfContents)
{
    m_N = numOfContents - 1;

    // NS_LOG_DEBUG (m_q << " and " << m_s << " and " << m_N);

    m_Pcum = std::vector<double> (m_N + 1);

    m_Pcum[0] = 0.0;
    for (uint32_t i=1; i<=m_N; i++)
    {
        m_Pcum[i] = m_Pcum[i-1] + 1.0 / std::pow(i+m_q, m_s);
    }

    for (uint32_t i=1; i<=m_N; i++)
    {
        m_Pcum[i] = m_Pcum[i] / m_Pcum[m_N];
        // NS_LOG_LOGIC ("Cumulative probability [" << i << "]=" << m_Pcum[i]);
    }
}

uint32_t CnmrClient::GetNumberOfContents () const
{
    return m_N;
}

void CnmrClient::SetQ (double q)
{
    m_q = q;
    SetNumberOfContents (m_N);
}

double CnmrClient::GetQ () const
{
    return m_q;
}

void CnmrClient::SetS (double s)
{
    m_s = s;
    SetNumberOfContents (m_N);
}

double CnmrClient::GetS () const
{
    return m_s;
}

} // namespace ndn
} // namespace ns3
