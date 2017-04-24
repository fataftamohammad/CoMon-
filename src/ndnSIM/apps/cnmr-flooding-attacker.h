#ifndef NDN_FLOODING_ATTACKER_H_
#define NDN_FLOODING_ATTACKER_H_

#include "ndn-app.h"
#include "ns3/random-variable.h"
#include "ns3/ndn-name.h"
#include "ns3/nstime.h"
#include "ns3/data-rate.h"
#include "ns3/ndn-rtt-estimator.h"

namespace ns3 {
namespace ndn {

class CnmrFloodingAttacker : public App
{
public:
    static const uint32_t FLAG = 600;

    static TypeId GetTypeId();

    CnmrFloodingAttacker();

protected:
    double              m_frequency; // Frequency of interest packets
    uint32_t            m_seqMin;

    // Random number generator for content IDs
    UniformVariable     m_randomSeqId;

    // Random number generator for inter-interest gaps
    RandomVariable      m_randomTime;

    // nonce generator
    UniformVariable m_randNonce;

    Time m_startAt;
    Time m_stopAt;
    Time m_interestLifeTime;

    EventId m_sendEvent;
    Name m_interestName;

    virtual void StartApplication ();
    virtual void StopApplication ();

    /**
     * \brief Constructs the Interest packet and sends it using a callback to the underlying NDN protocol
     */
    virtual void ScheduleNextPacket ();

    /**
     * @brief Actually send packet
     */
    void SendPacket ();

    uint32_t GetNextSeq();
};

} // namespace ndn
} // namespace ns3

#endif
