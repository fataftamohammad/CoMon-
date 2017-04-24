#include "hops-tracer.h"
#include "ns3/ndnSIM/utils/ndn-fw-hop-count-tag.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/config.h"
#include "ns3/names.h"
#include "ns3/callback.h"

#include "ns3/ndn-app.h"
#include "ns3/ndn-interest.h"
#include "ns3/ndn-data.h"
#include "ns3/simulator.h"
#include "ns3/node-list.h"
#include "ns3/log.h"

#include <boost/lexical_cast.hpp>

#include "ns3/ndnSIM/apps/cnmr-server.h"
#include "monitor-app.h"

#include <fstream>
#include <boost/lexical_cast.hpp>

NS_LOG_COMPONENT_DEFINE ("ndn.HopsTracer");

using namespace std;

namespace ns3 {
namespace ndn {

static std::list< boost::tuple< boost::shared_ptr<std::ostream>, std::list<Ptr<HopsTracer> > > > g_tracers;

template<class T>
static inline void
NullDeleter (T *ptr)
{
}

void
HopsTracer::Destroy ()
{
    g_tracers.clear ();
}

    void
HopsTracer::InstallAll (const std::string &file, Time averagingPeriod/* = Seconds (0.5)*/)
{
    using namespace boost;
    using namespace std;

    std::list<Ptr<HopsTracer> > tracers;
    boost::shared_ptr<std::ostream> outputStream;
    if (file != "-")
    {
        boost::shared_ptr<std::ofstream> os (new std::ofstream ());
        os->open (file.c_str (), std::ios_base::out | std::ios_base::trunc);

        if (!os->is_open ())
        {
            NS_LOG_ERROR ("File " << file << " cannot be opened for writing. Tracing disabled");
            return;
        }

        outputStream = os;
    }
    else
    {
        outputStream = boost::shared_ptr<std::ostream> (&std::cout, NullDeleter<std::ostream>);
    }

    for (NodeList::Iterator node = NodeList::Begin ();
            node != NodeList::End ();
            node++)
    {
        Ptr<HopsTracer> trace = Install (*node, outputStream, averagingPeriod);
        tracers.push_back (trace);
    }

    g_tracers.push_back (boost::make_tuple (outputStream, tracers));
}

    void
HopsTracer::Install (const NodeContainer &nodes, const std::string &file, Time averagingPeriod/* = Seconds (0.5)*/)
{
    using namespace boost;
    using namespace std;

    std::list<Ptr<HopsTracer> > tracers;
    boost::shared_ptr<std::ostream> outputStream;
    if (file != "-")
    {
        boost::shared_ptr<std::ofstream> os (new std::ofstream ());
        os->open (file.c_str (), std::ios_base::out | std::ios_base::trunc);

        if (!os->is_open ())
        {
            NS_LOG_ERROR ("File " << file << " cannot be opened for writing. Tracing disabled");
            return;
        }

        outputStream = os;
    }
    else
    {
        outputStream = boost::shared_ptr<std::ostream> (&std::cout, NullDeleter<std::ostream>);
    }

    for (NodeContainer::Iterator node = nodes.Begin ();
            node != nodes.End ();
            node++)
    {
        Ptr<HopsTracer> trace = Install (*node, outputStream, averagingPeriod);
        tracers.push_back (trace);
    }

    g_tracers.push_back (boost::make_tuple (outputStream, tracers));
}

    void
HopsTracer::Install (Ptr<Node> node, const std::string &file, Time averagingPeriod/* = Seconds (0.5)*/)
{
    using namespace boost;
    using namespace std;

    std::list<Ptr<HopsTracer> > tracers;
    boost::shared_ptr<std::ostream> outputStream;
    if (file != "-")
    {
        boost::shared_ptr<std::ofstream> os (new std::ofstream ());
        os->open (file.c_str (), std::ios_base::out | std::ios_base::trunc);

        if (!os->is_open ())
        {
            NS_LOG_ERROR ("File " << file << " cannot be opened for writing. Tracing disabled");
            return;
        }

        outputStream = os;
    }
    else
    {
        outputStream = boost::shared_ptr<std::ostream> (&std::cout, NullDeleter<std::ostream>);
    }

    Ptr<HopsTracer> trace = Install (node, outputStream, averagingPeriod);
    tracers.push_back (trace);

    g_tracers.push_back (boost::make_tuple (outputStream, tracers));
}


    Ptr<HopsTracer>
HopsTracer::Install (Ptr<Node> node,
        boost::shared_ptr<std::ostream> outputStream,
        Time averagingPeriod/* = Seconds (0.5)*/)
{
    NS_LOG_DEBUG ("Node: " << node->GetId ());

    Ptr<HopsTracer> trace = Create<HopsTracer> (outputStream, node);
    // trace->SetAveragingPeriod (averagingPeriod);

    return trace;
}

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

    HopsTracer::HopsTracer (boost::shared_ptr<std::ostream> os, Ptr<Node> node)
    : m_nodePtr (node)
      , m_os (os)
{
    m_node = boost::lexical_cast<string> (m_nodePtr->GetId ());

    Connect ();

    string name = Names::FindName (node);
    if (!name.empty ())
    {
        m_node = name;
    }
}

    HopsTracer::HopsTracer (boost::shared_ptr<std::ostream> os, const std::string &node)
    : m_node (node)
      , m_os (os)
{
    Connect ();
}

HopsTracer::~HopsTracer () {};


void
HopsTracer::Connect ()
{
    if(m_nodePtr->GetNApplications() > 0)
    {
        // Node has at least one application
        Ptr<ndn::CnmrServer> server = m_nodePtr->GetApplication(0)->GetObject<ndn::CnmrServer>();
        if(server != NULL)
        {
            // Node has a server application -> attach to it
            server->TraceConnectWithoutContext("InterestConsumed", MakeCallback (&HopsTracer::InterestConsumed, this));
        }

        Ptr<ndn::MonitorApp> monitor = m_nodePtr->GetApplication(0)->GetObject<ndn::MonitorApp>();
        if(monitor != NULL)
        {
            // Node has a monitor  application -> attach to it
            monitor->TraceConnectWithoutContext("InterestConsumed", MakeCallback (&HopsTracer::InterestConsumed, this));
        }
    }

    Ptr<fw::MonitorAwareRouting> mar = m_nodePtr->GetObject<fw::MonitorAwareRouting> ();
    mar->TraceConnectWithoutContext ("InterestConsumed", MakeCallback (&HopsTracer::InterestConsumed, this));
}

void HopsTracer::InterestConsumed (Ptr<const Interest> interest, bool printLastHop, bool legitimate = true)
{
    FwHopCountTag hopCountTag;
    interest->GetPayload ()->PeekPacketTag (hopCountTag);

    std::vector<uint32_t> hops = hopCountTag.GetHops();

    // First hop is the sender
    *m_os <<  hops[0] << " " << interest->GetName() << " ";

    std::vector<uint32_t>::const_iterator end = hops.end();
    if(!printLastHop)
    {
        end--;
    }
   
    *m_os << hops.size() << "\n";
}

} // namespace ndn
} // namespace ns3
