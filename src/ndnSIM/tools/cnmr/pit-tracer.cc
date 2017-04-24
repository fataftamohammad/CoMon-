#include "pit-tracer.h"
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

#include "monitor-app.h"

#include <fstream>

NS_LOG_COMPONENT_DEFINE ("ndn.PitTracer");

using namespace std;

namespace ns3 {
namespace ndn {

static std::list< boost::tuple< boost::shared_ptr<std::ostream>, std::list<Ptr<PitTracer> > > > g_tracers;

template<class T>
static inline void
NullDeleter (T *ptr)
{
}

void
PitTracer::Destroy ()
{
    g_tracers.clear ();
}

    void
PitTracer::InstallAll (const std::string &file, Time averagingPeriod/* = Seconds (0.5)*/)
{
    using namespace boost;
    using namespace std;

    std::list<Ptr<PitTracer> > tracers;
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
        Ptr<PitTracer> trace = Install (*node, outputStream, averagingPeriod);
        tracers.push_back (trace);
    }

    if (tracers.size () > 0)
    {
        tracers.front ()->PrintHeader (*outputStream);
        *outputStream << "\n";
    }

    g_tracers.push_back (boost::make_tuple (outputStream, tracers));
}

    void
PitTracer::Install (const NodeContainer &nodes, const std::string &file, Time averagingPeriod/* = Seconds (0.5)*/)
{
    using namespace boost;
    using namespace std;

    std::list<Ptr<PitTracer> > tracers;
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
        Ptr<PitTracer> trace = Install (*node, outputStream, averagingPeriod);
        tracers.push_back (trace);
    }

    if (tracers.size () > 0)
    {
        // *m_l3RateTrace << "# "; // not necessary for R's read.table
        tracers.front ()->PrintHeader (*outputStream);
        *outputStream << "\n";
    }

    g_tracers.push_back (boost::make_tuple (outputStream, tracers));
}

    void
PitTracer::Install (Ptr<Node> node, const std::string &file, Time averagingPeriod/* = Seconds (0.5)*/)
{
    using namespace boost;
    using namespace std;

    std::list<Ptr<PitTracer> > tracers;
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

    Ptr<PitTracer> trace = Install (node, outputStream, averagingPeriod);
    tracers.push_back (trace);

    if (tracers.size () > 0)
    {
        // *m_l3RateTrace << "# "; // not necessary for R's read.table
        tracers.front ()->PrintHeader (*outputStream);
        *outputStream << "\n";
    }

    g_tracers.push_back (boost::make_tuple (outputStream, tracers));
}


    Ptr<PitTracer>
PitTracer::Install (Ptr<Node> node,
        boost::shared_ptr<std::ostream> outputStream,
        Time averagingPeriod/* = Seconds (0.5)*/)
{
    NS_LOG_DEBUG ("Node: " << node->GetId ());

    Ptr<PitTracer> trace = Create<PitTracer> (outputStream, node);
    trace->SetAveragingPeriod (averagingPeriod);

    return trace;
}

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

    PitTracer::PitTracer (boost::shared_ptr<std::ostream> os, Ptr<Node> node)
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

    PitTracer::PitTracer (boost::shared_ptr<std::ostream> os, const std::string &node)
    : m_node (node)
      , m_os (os)
{
    Connect ();
}

PitTracer::~PitTracer ()
{
};


    void
PitTracer::Connect ()
{
    mar = m_nodePtr->GetObject<fw::MonitorAwareRouting> ();
    mar->TraceConnectWithoutContext ("PITUsage", MakeCallback (&PitTracer::PitUsage, this));

    mar->TraceConnectWithoutContext ("EntriesSatisfiedBefore", MakeCallback (&PitTracer::EntriesSatisfiedBefore, this));
    mar->TraceConnectWithoutContext ("MaliciousRequestedMulti", MakeCallback (&PitTracer::MaliciousRequestedMulti, this));
    mar->TraceConnectWithoutContext ("RequestedContentInterface", MakeCallback (&PitTracer::RequestedContentInterface, this));

    Reset();
}


    void
PitTracer::SetAveragingPeriod (const Time &period)
{
    m_period = period;
    m_printEvent.Cancel ();
    m_printEvent = Simulator::Schedule (m_period, &PitTracer::PeriodicPrinter, this);
}

    void
PitTracer::PeriodicPrinter ()
{
    Print (*m_os);
    Reset ();

    m_printEvent = Simulator::Schedule (m_period, &PitTracer::PeriodicPrinter, this);
}

void
PitTracer::PrintHeader (std::ostream &os) const
{
    os << "Time" << "\t"
        << "Node" << "\t"
        << "InFace" << "\t"
        << "Content" << "\t"
        << "Frequency" << "\t";
}

    void
PitTracer::Reset ()
{
    usage = 0;
    entries = 0;
    entriesSatisfiedBefore = 0;
    maliciousRequestedMulti = 0;
    requests.clear();
}

#define PRINTER(inface, content, freq)           \
  os << time.ToDouble (Time::S) << "\t"         \
  << m_node << "\t"                             \
  << inface << "\t"                          \
  << content << "\t"                          \
  << freq << "\n";

void
PitTracer::Print (std::ostream &os) const
{
    Time time = Simulator::Now ();
    for(std::map<uint32_t, std::map<Name,long long> >::const_iterator it = requests.begin(); it != requests.end(); it++)
    {
        for(std::map<Name, long long>::const_iterator cs = (it->second).begin(); cs != (it->second).end(); cs++)
        {
            PRINTER(it->first, cs->first, cs->second);
        }
    }

}

void PitTracer::PitUsage (double usage, uint32_t entries)
{
    this->usage = usage;
    this->entries = entries;
}

void PitTracer::EntriesSatisfiedBefore(uint32_t entries)
{
    this->entriesSatisfiedBefore = entries;
}

void PitTracer::MaliciousRequestedMulti(uint32_t entries)
{
    this->maliciousRequestedMulti = entries;
}

void PitTracer::RequestedContentInterface(uint32_t InFace, Name Content)
{
    (this->requests)[InFace][Content]++;
}
} // namespace ndn
} // namespace ns3
