#ifndef CNMR_SERVER_H_
#define CNMR_SERVER_H_

#include "ndn-app.h"

#include "ns3/ndnSIM/model/fw/monitor-aware-routing.h"

#include "ns3/ptr.h"
#include "ns3/ndn-name.h"
#include "ns3/ndn-data.h"

namespace ns3 {
namespace ndn {

class CnmrServer : public App
{
public:
    static TypeId
    GetTypeId (void);

    CnmrServer ();

    void OnInterest (Ptr<const Interest> interest);

protected:
    virtual void StartApplication ();
    virtual void StopApplication ();

private:
    Name m_prefix;
    Name m_postfix;
    uint32_t m_numContent;;
    uint32_t m_virtualPayloadSize;
    Time m_freshness;

    uint32_t m_signature;
    Name m_keyLocator;

    TracedCallback<Ptr<const Interest>, bool, bool> interestConsumedTrace;

    Ptr<ndn::fw::MonitorAwareRouting> mar;
};

} // namespace ndn
} // namespace ns3

#endif
