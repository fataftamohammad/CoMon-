/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2011 UCLA
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Xiaoyan Hu <x......u@gmail.com>
 *         Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "ndn-cs-tracer.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/config.h"
#include "ns3/names.h"
#include "ns3/callback.h"

#include <ns3/name.h>

#include "ns3/ndn-app.h"
#include "ns3/ndn-interest.h"
#include "ns3/ndn-data.h"
#include "ns3/ndn-content-store.h"
#include "ns3/simulator.h"
#include "ns3/node-list.h"
#include "ns3/log.h"

#include <boost/lexical_cast.hpp>

#include <fstream>
#include <map>

NS_LOG_COMPONENT_DEFINE ("ndn.CsTracer");

using namespace std;

namespace ns3 {
namespace ndn {

static std::list< boost::tuple< boost::shared_ptr<std::ostream>, std::list<Ptr<CsTracer> > > > g_tracers;

template<class T>
static inline void
NullDeleter (T *ptr)
{
}

void
CsTracer::Destroy ()
{
  g_tracers.clear ();
}

void
CsTracer::InstallAll (const std::string &file, Time startTime, Time finishTime/* = Seconds (0.5)*/)
{
  using namespace boost;
  using namespace std;
  
  std::list<Ptr<CsTracer> > tracers;
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
      Ptr<CsTracer> trace = Install (*node, outputStream, startTime, finishTime);
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
CsTracer::Install (const NodeContainer &nodes, const std::string &file, Time startTime, Time finishTime/* = Seconds (0.5)*/)
{
  using namespace boost;
  using namespace std;

  std::list<Ptr<CsTracer> > tracers;
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
      Ptr<CsTracer> trace = Install (*node, outputStream, startTime, finishTime);
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
CsTracer::Install (Ptr<Node> node, const std::string &file, Time startTime, Time finishTime/* = Seconds (0.5)*/)
{
  using namespace boost;
  using namespace std;

  std::list<Ptr<CsTracer> > tracers;
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

  Ptr<CsTracer> trace = Install (node, outputStream, startTime, finishTime);
  tracers.push_back (trace);

  if (tracers.size () > 0)
    {
      // *m_l3RateTrace << "# "; // not necessary for R's read.table
      tracers.front ()->PrintHeader (*outputStream);
      *outputStream << "\n";
    }

  g_tracers.push_back (boost::make_tuple (outputStream, tracers));
}


Ptr<CsTracer>
CsTracer::Install (Ptr<Node> node,
                   boost::shared_ptr<std::ostream> outputStream,
                   Time startTime, Time finishTime/* = Seconds (0.5)*/)
{
  NS_LOG_DEBUG ("Node: " << node->GetId ());

  Ptr<CsTracer> trace = Create<CsTracer> (outputStream, node);
  trace->SetTimes (startTime, finishTime);

  return trace;
}

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

CsTracer::CsTracer (boost::shared_ptr<std::ostream> os, Ptr<Node> node)
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

CsTracer::CsTracer (boost::shared_ptr<std::ostream> os, const std::string &node)
: m_node (node)
, m_os (os)
{
  Connect ();
}

CsTracer::~CsTracer ()
{
};


void
CsTracer::Connect ()
{
  Ptr<ContentStore> cs = m_nodePtr->GetObject<ContentStore> ();
  cs->TraceConnectWithoutContext ("CacheHits",   MakeCallback (&CsTracer::CacheHits,   this));
  cs->TraceConnectWithoutContext ("CacheMisses", MakeCallback (&CsTracer::CacheMisses, this));

  Reset ();  
}


void
CsTracer::SetTimes (const Time &periodS, const Time &periodF)
{
  m_startTime = periodS;
  m_finishTime = periodF;
  m_printEvent.Cancel ();
  m_printEvent = Simulator::Schedule (Seconds(20000.0), &CsTracer::PeriodicPrinter, this);
}

void
CsTracer::PeriodicPrinter ()
{
  Print (*m_os);
  Reset();
  m_printEvent = Simulator::Schedule (Seconds(20000.0), &CsTracer::PeriodicPrinter, this);

}

void
CsTracer::PrintHeader (std::ostream &os) const
{
  os << "Time" << "\t"
  	 << "Node" << "\t\t"
     << "Type" << "\t\t"
     << "Value";
}

void
CsTracer::Reset ()
{
  m_stats.Reset();
}

#define PRINTER_R(printName, a, b)            \
  os << time.ToDouble (Time::S) << "\t"       \
  << m_node << "\t\t\t"                         \
  << printName << "\t\t"                      \
  <<  a << "." << b << "%\n";

#define PRINTER_D(printName, b)				\
  os << time.ToDouble (Time::S) << "\t"								\
  	 << m_node << "\t\t\t"							\
  	 << printName << "\t\t"						\
  	 << b << "\n";

void
CsTracer::Print (std::ostream &os) const
{
  Time time = Simulator::Now ();  
  
  if(m_node[0]=='c')
  {     
    PRINTER_D ("TotalSentInterests", m_stats.m_cacheMisses);
  }
  else if(m_node[0]=='s')
  {
    PRINTER_D ("TotalReceivedInterests", m_stats.m_cacheMisses);
  }
  else if(m_node[0]=='a')
  {
  	PRINTER_D ("TotalSentInterests", m_stats.m_cacheMisses);
  }
  else
  {
    int x = m_stats.m_cacheHits * 1.0 / (m_stats.m_cacheHits + m_stats.m_cacheMisses) * 10000;
    PRINTER_D ("RR", m_stats.m_cacheHits + m_stats.m_cacheMisses);
    PRINTER_R ("HR", x/100, x%100);
    
    // PRINTER_D ("Name", "#ofRequests");
    
    // for(std::map<Name,long long>::const_iterator it = m_stats.pattern.begin(); it != m_stats.pattern.end(); it++)
    // {
    //   PRINTER_D(it->first, it->second)
    // }

  }
}

void 
CsTracer::CacheHits (Ptr<const Interest> interest, Ptr<const Data>)
{
  if(Time("2s") == interest->GetInterestLifetime())
    m_stats.m_cacheHits ++;

  // (m_stats.pattern)[interest->GetName()]++;

}

void 
CsTracer::CacheMisses (Ptr<const Interest> interest)
{
  if(Time("2s") == interest->GetInterestLifetime())
    m_stats.m_cacheMisses ++;
  
    // (m_stats.pattern)[interest->GetName()]++;
}


} // namespace ndn
} // namespace ns3
