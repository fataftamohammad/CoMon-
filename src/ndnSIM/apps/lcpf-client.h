#ifndef LCPF_CLIENT_H_
#define LCPF_CLIENT_H_

#include "ndn-consumer.h"
#include <vector>

namespace ns3 {
namespace ndn {

class LcpfClient: public Consumer
{
public:
    static TypeId GetTypeId ();

    LcpfClient();

    void SetPrefixes(std::string p);

protected:
    void StartApplication ();

    /**
    * \brief Constructs the Interest packet and sends it using a callback to the underlying NDN protocol
    */
    virtual void ScheduleNextPacket ();

    /**
    * @brief Actually send packet
    */
    void SendPacket ();

    uint32_t GetNextSeq();

    double              m_frequency; // Frequency of interest packets (in hertz)

        // Random number generator for content IDs
    UniformVariable     m_SeqRng;

    // Random number generator for inter-interest gaps
    RandomVariable      *m_random;

    // Random number generator for choosing a random prefix
    RandomVariable      *rngPrefix;

    uint32_t m_N;  //number of the contents
    double m_q;  //q in (k+q)^s
    double m_s;  //s in (k+q)^s
    std::vector<double> m_Pcum;  //cumulative probability

    std::string m_p; //prefixes in one string seperated by commas.

private:
    void SetNumberOfContents (uint32_t numOfContents);
    uint32_t GetNumberOfContents () const;
    void SetQ (double q);
    double GetQ () const;
    void SetS (double s);
    double GetS () const;


    std::vector<Name> prefixes;
    Name &GetNextPrefix(uint32_t);

};

} // namespace ndn
} // namespace ns3

#endif
