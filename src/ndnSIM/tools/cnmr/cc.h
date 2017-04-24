#ifndef CC_H_
#define CC_H_

#include "ns3/node.h"
#include <fstream>
#include <vector>

#include "monitor-app.h"

#include "ns3/core-module.h"
#include "ns3/ndn-app.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/point-to-point-layout-module.h"
#include "ns3/ndnSIM-module.h"
#include "ns3/topology-reader.h"
#include "ns3/config-store.h"
#include "ns3/gtk-config-store.h"

#include "ns3/ndnSIM/model/fw/monitor-aware-routing.h"
#include "ns3/ndnSIM/apps/cnmr-flooding-attacker.h"
#include "ns3/ndnSIM/apps/cnmr-client.h"

// #include "cnmr/pit-tracer.h"
// #include "cnmr/cc.h"

#include <sys/stat.h>
#include <math.h>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>
#include "ns3/ndn-content-store.h"

namespace ns3 {
namespace ndn {

typedef std::map<Name,uint32_t>::iterator mpIterator;

class CC
{
public:
    CC();
    ~CC();

    static void report(Ptr<Node> node, CNMRReport report);
    static void setFilename(std::string filename);
    static void setNormalRouters(NodeContainer _routers);
    static void setCacheSize(uint32_t sz);

private:
    NodeContainer normalRouters;
    uint32_t pitSize;
    uint32_t cacheSize;
    float gamma;

    std::string filename;
    std::ofstream os;

    // The CC saves the last report it has sent to CNMRs to be able to detect when an attack stopped
    std::set<Name> lastReportedPrefixes;
    std::map<uint32_t, Ptr<Node> > monitors;

    typedef std::map<uint32_t, std::vector<std::pair<int, int> > >  NodePairsMap;

    // The interval at which CC information should be printed (seconds) to file for evaluation
    uint32_t intervalPrint;

    double sizeReports;
    double sizeMessagesSent;
    double sizeMessagesReceived;
    uint32_t numMessagesSent;
    uint32_t numMessagesReceived;

    std::map<Name,uint32_t> requestsPerName;

    static double getSizeReport(CNMRReport &report);

    void print(void);

    void onTimerPrint(void);

    void checkForAttack(void);

    typedef std::map<uint32_t, std::vector<CNMRReport> > ReportMap;
    ReportMap reportsCurrentPeriod;
    std::map<uint32_t, CNMRReport> lastReports;
    int interests_received;
    int cache_hits;
    void setContentsToCache();
};

} // namespace ndn
} // namespace ns3

#endif
