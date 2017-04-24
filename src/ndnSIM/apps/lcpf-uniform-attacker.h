#ifndef LCPF_UNIFORM_ATTACKER_H_
#define LCPF_UNIFORM_ATTACKER_H_

#include "ndn-app.h"
#include "ns3/ndnSIM/model/ndn-common.h"
#include "ns3/random-variable.h"
#include "ns3/ndn-name.h"
#include "ns3/nstime.h"
#include "ns3/data-rate.h"
#include "ns3/ndn-rtt-estimator.h"

namespace ns3 {
namespace ndn {

class LcpfUniformAttacker : public App
{
public:
    static TypeId GetTypeId();

    LcpfUniformAttacker();

    void SetPrefixes(std::string p);
protected:
    double              m_frequency; // Frequency of interest packets
    double              m_relativeSetSize;
    uint32_t            m_numberOfContents;

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
    std::string m_p;

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

    std::vector<Name> prefixes;

    Name &GetNextPrefix(uint32_t);

    void
    SetNumberOfContents(uint32_t numOfContents);

    uint32_t
    GetNumberOfContents() const;
};

} // namespace ndn
} // namespace ns3

#endif
