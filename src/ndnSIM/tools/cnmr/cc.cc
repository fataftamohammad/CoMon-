#include "cc.h"
#include "ns3/core-module.h"
#include "ns3/log.h"
#include "ns3/simulation-singleton.h"

#include <boost/foreach.hpp>
#include <typeinfo>


#include "ns3/packet.h"

#include "ns3/ndn-interest.h"

#include "ns3/ndn-data.h"


NS_LOG_COMPONENT_DEFINE ("CC");

namespace ns3 {
namespace ndn {

using namespace fw;

static GlobalValue g_gamma("gamma",
        "",
        ns3::DoubleValue (0.2),
        ns3::MakeDoubleChecker<float> (0, 1));

CC::CC()
{
    period_pos = 0;
    // The interval at which the CC prints stats to the evaluation file
    intervalPrint = 2000;
    Simulator::Schedule(Seconds(intervalPrint), &CC::onTimerPrint, this);

    UintegerValue v_pitSize;
    GlobalValue::GetValueByName("PITSize", v_pitSize);
    pitSize = v_pitSize.Get();

    DoubleValue v_gamma;
    g_gamma.GetValue(v_gamma);
    gamma = v_gamma.Get();
}

CC::~CC()
{
    os.close();
}

void CC::report(Ptr<ns3::Node> node, CNMRReport report)
{
    printf("Report\n");
    // Get the singleton of the CC
    CC *cc = SimulationSingleton<CC>::Get();

    // Count the number of control messages received
    cc->numMessagesReceived++;

    uint32_t nodeId = node->GetId();

    if(cc->monitors[nodeId] == 0)
    {
        // Save a reference to every monitor that reports to the CC, so that the CC can report back
        // to those monitors
        cc->monitors[nodeId] = node;//
    }

    // Just save the report
    cc->reportsCurrentPeriod[nodeId].push_back(report);
    cc->lastReports[nodeId] = report;

    // Calculate the size of the report
    double sizeMsg = cc->getSizeReport(report);
    cc->sizeReports += sizeMsg;
    cc->sizeMessagesReceived += sizeMsg;
    cc->numMessagesReceived++;
    cc->interests_received+=report.interestsReceived;
    cc->cache_hits+=report.cacheHits;

    for (mpIterator it = report.requestsPerName.begin(); it != report.requestsPerName.end(); ++it)
        cc->requestsPerName[it->first]+=it->second;

    // cc->checkForAttack();
}

void CC::checkForAttack(void)
{
    // // printf("CheckAttack\n");
    // std::set<Name> maliciousPrefixes;

    // std::map<Name, std::vector<int> > timedOutEntriesPerName;

    // // Aggregate reported PIT usages of nodes and check if the usage of one prefix is above threshold
    // for(std::map<uint32_t, CNMRReport>::const_iterator it = lastReports.begin(); it != lastReports.end(); ++it)
    // {
    //     CNMRReport report = it->second;
    //     for(MonitorAwareRouting::PerNameCounter::iterator count = report.timedOutEntriesPerName.begin(); count != report.timedOutEntriesPerName.end(); ++count)
    //     {
    //         timedOutEntriesPerName[count->first].push_back(count->second);
    //     }
    // }

    // std::pair<Name, std::vector<int> > d;
    // BOOST_FOREACH(d, timedOutEntriesPerName)
    // {
    //     uint32_t numTimedOut = 0;
    //     BOOST_FOREACH(int i, d.second)
    //     {
    //         numTimedOut += i;
    //     }

    //     float expireRatio = (float)numTimedOut / pitSize;

    //     if(expireRatio >= gamma)
    //     {
    //         maliciousPrefixes.insert(d.first);
    //     }
    // }

    // // If the determined malicious prefix are different from the prefixes that the CC reported as
    // // malicious the last time, report it!
    // if(maliciousPrefixes != lastReportedPrefixes)
    // {
    //     // the name for routing the control message, e.g. /cc/control_message/
    //     double sizeMsg = sizeof(Name) + sizeof(uint32_t) + (maliciousPrefixes.size() * sizeof(Name));
    //     sizeReports += sizeMsg;
    //     numMessagesSent++;
    //     sizeMessagesSent += sizeMsg;

    //     lastReportedPrefixes = maliciousPrefixes;

    //     // Report to CNMRs
    //     for(std::map<uint32_t, Ptr<ndn::fw::MonitorAwareRouting> >::const_iterator it = monitors.begin(); it != monitors.end(); ++it)
    //     {
    //         it->second->setMaliciousPrefixes(maliciousPrefixes);
    //     }

    // }
}

void CC::setFilename(std::string filename)
{
    SimulationSingleton<CC>::Get()->filename = filename;
    SimulationSingleton<CC>::Get()->os.open(filename.c_str());

    if (!SimulationSingleton<CC>::Get()->os.is_open ())
    {
        std::cout << "Could not open file for CC trace. Not writing..." << std::endl;
    }
    else
    {
        // Print header to file
        SimulationSingleton<CC>::Get()->os << "Time\tNode\tFace\tSignal\tValue\n";
    }
}



/**
 * Print to evaluation file
 */
void CC::print(void)
{
    // printf("PRINT\n");
    if(reportsCurrentPeriod.size() == 0)
        // No reports -> don't print to file
        return;

    Time time = Simulator::Now ();

    // os << time.ToDouble(Time::S) << "\tCC\tall\t" << "Overhead\t" << sizeReports << "\n";
    os << time.ToDouble(Time::S) << "\tCC\tall\t" << "NumReceived\t" << numMessagesReceived << "\n";
    os << time.ToDouble(Time::S) << "\tCC\tall\t" << "NumSent\t" << numMessagesSent << "\n";
    os << time.ToDouble(Time::S) << "\tCC\tall\t" << "SizeReceived\t" << sizeMessagesReceived << "\n";
    os << time.ToDouble(Time::S) << "\tCC\tall\t" << "SizeSent\t" << sizeMessagesSent << "\n";
    os << time.ToDouble(Time::S) << "\tCC\tall\t" << "interestsReceived\t" << interests_received << "\n";
    os << time.ToDouble(Time::S) << "\tCC\tall\t" << "cacheHits\t" << cache_hits << "\n";
    os << time.ToDouble(Time::S) << "\tCC\tall\t" << "cacheHitRatio\t" << 1.0*cache_hits/interests_received << "\n";

    os.flush();

    // Reset stats
    interests_received = cache_hits = 0;
    reportsCurrentPeriod.clear();
    sizeReports = 0;
    numMessagesSent = 1;
    numMessagesReceived = 0;
    sizeMessagesSent = 0;
    sizeMessagesReceived = 0;
    requestsPerName.clear();

}

void CC::onTimerPrint(void)
{
    // printf("TimerPrint\n");
    // Print to file
    SimulationSingleton<CC>::Get()->setContentsToCache();
    SimulationSingleton<CC>::Get()->print();

    Simulator::Schedule(Seconds(intervalPrint), &CC::onTimerPrint, this);
}

/**
 * Returns the size of the report if it would have been transmitted over the wire.
 */
double CC::getSizeReport(CNMRReport &report)
{
    // Important: keep this up to date

    double size = 0;

    // the name for routing the control message, e.g. /cc/control_message/
    size += 1 * sizeof(Name);

    // the name for routing the control message, e.g. /cc/control_message/
    size += 2 * sizeof(uint32_t);

    // size += report.timedOutEntriesPerName.size() * (sizeof(Name) + sizeof(uint32_t));
    size += sizeof(report.requestsPerName);

    return size;
}

//////////////////////////////////////////////////
////////////////////MY STUFF//////////////////////
//////////////////////////////////////////////////
void CC::setContentsToCache()
{
    return;
    const int w1 = 6, w2 = 3, w3 = 1;

    std::vector<std::pair<int,Name> >  contents_freq;
    for (mpIterator it = requestsPerName.begin(); it != requestsPerName.end(); ++it)
        contents_freq.push_back(std::make_pair(it->second,it->first));
    std::map<Name,int> curr_namesPositions;

    // printf("%d\n", contents_freq.size());
    std::sort(contents_freq.begin(), contents_freq.end());
    std::reverse(contents_freq.begin(), contents_freq.end());

    for (uint32_t i = 0; i < contents_freq.size(); ++i)
        curr_namesPositions[contents_freq[i].second] = cacheSize*monitors.size()*5 - i;

    contents_freq.clear();
    for(std::map<Name,int>::const_iterator it = curr_namesPositions.begin(); it != curr_namesPositions.end(); ++it)
    {
        Name name = it->first;
        int score = w1*it->second;
        score += w2*namesPositions[!period_pos][name] + w3*namesPositions[period_pos][name];
        contents_freq.push_back(std::make_pair(score,name));
    }
    std::sort(contents_freq.begin(), contents_freq.end());
    std::reverse(contents_freq.begin(), contents_freq.end());

    namesPositions[period_pos] = curr_namesPositions;
    period_pos^=1;

    std::set<Name> contentsInMonitors;
    for (uint32_t i = 0; i < cacheSize*monitors.size() && i<contents_freq.size(); ++i)
        contentsInMonitors.insert(contents_freq[i].second);


    std::map<Name,uint32_t> contents_id;
    std::set<Name>::iterator contents_it = contentsInMonitors.begin();
    for(std::map<uint32_t, Ptr<Node> >::const_iterator it = monitors.begin(); it != monitors.end(); ++it)
    {

        Ptr<ContentStore> m_contentStore = it->second->GetObject<ContentStore> ();

        Ptr<Interest> newInterest = Create<Interest> ();
        newInterest->SetName (Create<Name> ("/ADD_EN"));
        // m_contentStore->Lookup(newInterest);

        for (int i = 0; i < (int)cacheSize; ++i)
        {
              Ptr<Data> data = Create<Data> (Create<Packet> (1024));//m_virtualPayloadSize
              Ptr<Name> dataName = Create<Name> (*contents_it);


              data->SetName (dataName);

              // data->SetFreshness (TimeValue (Seconds (0)));//m_freshness
              data->SetTimestamp (Simulator::Now());

              data->SetSignature (3);//2 from producer, 3 from cache.
              m_contentStore->Add(data);

              contents_id[*contents_it] = it->first;
              std::advance(contents_it,1);
              if(contents_it == contentsInMonitors.end())
                contents_it = contentsInMonitors.begin();

        }
        Ptr<Interest> newInterest2 = Create<Interest> ();

        newInterest2->SetName (Create<Name> ("/ADD_DIS"));
        m_contentStore->Lookup(newInterest2);
    }

    for(std::map<uint32_t, Ptr<Node> >::const_iterator it = monitors.begin(); it != monitors.end(); ++it)
    {
        // printf("%u\n",it->first );
        Ptr<ndn::fw::MonitorAwareRouting> m_fw = it->second->GetObject<ndn::fw::MonitorAwareRouting>();
        m_fw->setContentMonitorID(contents_id);
    }


   for(NodeContainer::iterator it = normalRouters.begin(); it != normalRouters.End(); ++it)
   {
        Ptr<Node> curr = *it;
        // printf("In Loop\n");
        curr->GetObject<ndn::fw::MonitorAwareRouting>()->setNotForCache(contentsInMonitors);
   } 
   sizeMessagesSent += sizeof(requestsPerName)*normalRouters.size();
   sizeMessagesSent += sizeof(contents_id)*monitors.size() + sizeof(Name)*2*monitors.size();
}


void CC::setNormalRouters(ns3::NodeContainer _routers)
{
    SimulationSingleton<CC>::Get()->normalRouters = _routers;
}

void CC::setCacheSize(uint32_t sz)
{
    SimulationSingleton<CC>::Get()->cacheSize = sz;
}

} // namespace ndn
} // namespace ns3
