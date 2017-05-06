/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2011 University of California, Los Angeles
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
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_CONTENT_STORE_IMPL_H_
#define NDN_CONTENT_STORE_IMPL_H_

#include "ndn-content-store.h"
#include "ns3/packet.h"
#include "ns3/ndn-interest.h"
#include "ns3/ndn-data.h"
#include <boost/foreach.hpp>

#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ns3/string.h"

#include "../../utils/trie/trie-with-policy.h"

#include <cstdio>
#include "ns3/ptr.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/packet.h"
#include "ns3/callback.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/random-variable-stream.h"
#include "ns3/integer.h"

#include <ctime>
using namespace ns3;


namespace ns3 {
namespace ndn {
namespace cs {

/**
 * @ingroup ndn-cs
 * @brief Cache entry implementation with additional references to the base container
 */
template<class CS>
class EntryImpl : public Entry
{
public:
  typedef Entry base_type;

public:
  EntryImpl (Ptr<ContentStore> cs, Ptr<const Data> data)
    : Entry (cs, data)
    , item_ (0)
  {
  }

  void
  SetTrie (typename CS::super::iterator item)
  {
    item_ = item;
  }

  typename CS::super::iterator to_iterator () { return item_; }
  typename CS::super::const_iterator to_iterator () const { return item_; }

private:
  typename CS::super::iterator item_;
};



/**
 * @ingroup ndn-cs
 * @brief Base implementation of NDN content store
 */
template<class Policy>
class ContentStoreImpl : public ContentStore,
                         protected ndnSIM::trie_with_policy< Name,
                                                             ndnSIM::smart_pointer_payload_traits< EntryImpl< ContentStoreImpl< Policy > >, Entry >,
                                                             Policy >
{
public:
  typedef ndnSIM::trie_with_policy< Name,
                                    ndnSIM::smart_pointer_payload_traits< EntryImpl< ContentStoreImpl< Policy > >, Entry >,
                                    Policy > super;

  typedef EntryImpl< ContentStoreImpl< Policy > > entry;

  static TypeId
  GetTypeId ();

  ContentStoreImpl () ;
  virtual ~ContentStoreImpl () { };

  // from ContentStore

  virtual inline Ptr<Data>
  Lookup (Ptr<const Interest> interest);

  virtual inline bool
  Add (Ptr<const Data> data);

  // virtual bool
  // Remove (Ptr<Interest> header);

  virtual inline void
  Print (std::ostream &os) const;

  virtual uint32_t
  GetSize () const;

  virtual Ptr<Entry>
  Begin ();

  virtual Ptr<Entry>
  End ();

  virtual Ptr<Entry>
  Next (Ptr<Entry>);

  const typename super::policy_container &
  GetPolicy () const { return super::getPolicy (); }

  typename super::policy_container &
  GetPolicy () { return super::getPolicy (); }
  bool attackDetection(Name name);



private:
  void
  SetMaxSize (uint32_t maxSize);

  uint32_t
  GetMaxSize () const;

  bool
  toInsert(Name name);
  double
  sheildingFunction(int t);

  bool learningStep();
  bool attackTest();
  bool populateS(Name name);
  void RRTrace();
  void HRTrace();
  void RCountsTrace(Name name);

  std::string m_defenseType;

private:
  static LogComponent g_log; ///< @brief Logging variable

  /// @brief trace of for entry additions (fired every time entry is successfully added to the cache): first parameter is pointer to the CS entry
  TracedCallback< Ptr<const Entry> > m_didAddEntry;

  //////////////////////////////////////////////////////////////////////////////
  int mode; //1 accept add, 0 deny add.
  int RR;
  int HR;
  double curr_seconds_RR;
  double curr_seconds_HR;
  double curr_seconds_RCounts;
  double period_seconds;
  std::map<Name,int> RCounts;
  int defenceMethod; // 0 nothing, 1 CacheSheild, 2 lightweight
  ////CacheSheild////
  std::map<Name,int> mp_ContentsFrequency;

  ////Lightweight////
  std:: set<Name> s;
  unsigned int s_size;
  int snap_size;
  int analyzed_cos;
  std:: map<Name,int> co_count;
  std:: map<Name,double> co_freq;
  double taw; //Taw
  double sd; //standard deviation
  double mx_sd; //maximum standard deviation
  int contents_count;
  double mk,sk,k;//knuth

};

//////////////////////////////////////////
////////// Implementation ////////////////
//////////////////////////////////////////


template<class Policy>
LogComponent ContentStoreImpl< Policy >::g_log = LogComponent (("ndn.cs." + Policy::GetName ()).c_str ());


template<class Policy>
TypeId
ContentStoreImpl< Policy >::GetTypeId ()
{
  static TypeId tid = TypeId (("ns3::ndn::cs::"+Policy::GetName ()).c_str ())
    .SetGroupName ("Ndn")
    .SetParent<ContentStore> ()
    .AddConstructor< ContentStoreImpl< Policy > > ()
    .AddAttribute ("MaxSize",
                   "Set maximum number of entries in ContentStore. If 0, limit is not enforced",
                   StringValue ("100"),
                   MakeUintegerAccessor (&ContentStoreImpl< Policy >::GetMaxSize,
                                         &ContentStoreImpl< Policy >::SetMaxSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Defense",
                   "Defense used in cache",
                   StringValue("None"),
                   MakeStringAccessor (&ContentStoreImpl< Policy >::m_defenseType),
                   MakeStringChecker ())

    .AddAttribute ("ContentsCount",
               "The number of contents available for consumers",
               IntegerValue (1000),
               MakeIntegerAccessor (&ContentStoreImpl< Policy >::contents_count),
               MakeIntegerChecker<int> ())


    .AddTraceSource ("DidAddEntry", "Trace fired every time entry is successfully added to the cache",
                     MakeTraceSourceAccessor (&ContentStoreImpl< Policy >::m_didAddEntry))
    ;

  return tid;
}

struct isNotExcluded
{
  inline
  isNotExcluded (const Exclude &exclude)
    : m_exclude (exclude)
  {
  }
  
  bool
  operator () (const name::Component &comp) const
  {
    return !m_exclude.isExcluded (comp);
  }

private:
  const Exclude &m_exclude;
};

template<class Policy>
Ptr<Data>
ContentStoreImpl<Policy>::Lookup (Ptr<const Interest> interest)
{
  if(interest->GetName().toUri() == "/ADD_DIS")
  {
    mode = 0;

    return 0;
  }
  if(interest->GetName().toUri() == "/ADD_EN")
  {
    mode = 1;

    return 0;
  }
  RRTrace();
  RCountsTrace(interest->GetName());
  s_size = contents_count/100;////////////TO CHANGEEEEEEEE!!!!!!!!!
  NS_LOG_FUNCTION (this << interest->GetName ());
  if(m_defenseType == "LightWeight")
  {

    if(populateS(interest->GetName ())) //S is populated, start learning/detecting
    {
      if(attackDetection(interest->GetName()))//UNDER ATTACK!!!
      {
        // printf(" : UNDER ATTACK!!!");
      }
    }
    else
    {
    // printf("Lookup %s", interest->GetName().toUri().c_str());

      // printf(" : Adding to S(%lu)", s.size());
      // printf("\n");

    } 
  }

  typename super::const_iterator node;
  if (interest->GetExclude () == 0)
    {
      node = this->deepest_prefix_match (interest->GetName ());
    }
  else
    {
      node = this->deepest_prefix_match_if_next_level (interest->GetName (),
                                                       isNotExcluded (*interest->GetExclude ()));
    }

  if (node != this->end ())
    {
      this->m_cacheHitsTrace (interest, node->payload ()->GetData ());

      Ptr<Data> copy = Create<Data> (*node->payload ()->GetData ());
      ConstCast<Packet> (copy->GetPayload ())->RemoveAllPacketTags ();
      HRTrace(); //HIT
      return copy;
    }
  else
    {
      this->m_cacheMissesTrace (interest);
      return 0;
    }
}

template<class Policy>
bool
ContentStoreImpl<Policy>::Add (Ptr<const Data> data)
{
  // if(mode == 0)
  //   return 0;
  // return false;
  NS_LOG_FUNCTION (this << data->GetName ());
  // std::string data_name = data->GetName();

  

  if(m_defenseType == "CS") //CacheSheild
  {
    // printf("INSERT %s ",data->GetName().toUri().c_str());
    if(!toInsert(data->GetName()))
    {
      // std::cout<<" : CacheSheild - NO \n";
      return false;
    }
    // std::cout<<" : CacheSheild - YES ";
    // printf("\n");

  }
  Ptr< entry > newEntry = Create< entry > (this, data);
  std::pair< typename super::iterator, bool > result = super::insert (data->GetName (), newEntry);

  if (result.first != super::end ())
    {
      if (result.second)
        {
          newEntry->SetTrie (result.first);

          m_didAddEntry (newEntry);
          return true;
        }
      else
        {
          // should we do anything?
          // update payload? add new payload?
          return false;
        }
    }
  else
    return false; // cannot insert entry
}

template<class Policy>
void
ContentStoreImpl<Policy>::Print (std::ostream &os) const
{
  for (typename super::policy_container::const_iterator item = this->getPolicy ().begin ();
       item != this->getPolicy ().end ();
       item++)
    {
      os << item->payload ()->GetName () << std::endl;
    }
}

template<class Policy>
void
ContentStoreImpl<Policy>::SetMaxSize (uint32_t maxSize)
{
  this->getPolicy ().set_max_size (maxSize);
}

template<class Policy>
uint32_t
ContentStoreImpl<Policy>::GetMaxSize () const
{
  return this->getPolicy ().get_max_size ();
}

template<class Policy>
uint32_t
ContentStoreImpl<Policy>::GetSize () const
{
  return this->getPolicy ().size ();
}

template<class Policy>
Ptr<Entry>
ContentStoreImpl<Policy>::Begin ()
{
  typename super::parent_trie::recursive_iterator item (super::getTrie ()), end (0);
  for (; item != end; item++)
    {
      if (item->payload () == 0) continue;
      break;
    }

  if (item == end)
    return End ();
  else
    return item->payload ();
}

template<class Policy>
Ptr<Entry>
ContentStoreImpl<Policy>::End ()
{
  return 0;
}

template<class Policy>
Ptr<Entry>
ContentStoreImpl<Policy>::Next (Ptr<Entry> from)
{
  if (from == 0) return 0;

  typename super::parent_trie::recursive_iterator
    item (*StaticCast< entry > (from)->to_iterator ()),
    end (0);

  for (item++; item != end; item++)
    {
      if (item->payload () == 0) continue;
      break;
    }

  if (item == end)
    return End ();
  else
    return item->payload ();
}


/////////////////MY STUFF

////Initialization
template<class Policy>
ContentStoreImpl<Policy>::ContentStoreImpl ()
{
  // defenceMethod = 0;
  // printf(" contents count = %d\n", contents_count);
  snap_size = 10000;
  analyzed_cos = 0;
  taw = 0;
  sd = 0;
  mx_sd = 0;
  mk=sk=0;
  k=1;
  RR = HR = 0;
  curr_seconds_RR = curr_seconds_HR = Simulator::Now().GetSeconds();
  period_seconds = 10;
  mode = 1;
}



////TRACING
template<class Policy>
void
ContentStoreImpl<Policy>::RRTrace()
{
  RR++;
  double curr_seconds2 = Simulator::Now().GetSeconds();
  if(curr_seconds2-curr_seconds_RR>period_seconds) //MORE Than the period seconds!
  {
    // printf("RR: %d, time = %.3f\n",RR,Simulator::Now().GetSeconds());
    RR = 0;
    curr_seconds_RR = curr_seconds2;
  }
}


template<class Policy>
void
ContentStoreImpl<Policy>::HRTrace()
{
  RR++;
  double curr_seconds2 = Simulator::Now().GetSeconds();
  if(curr_seconds2-curr_seconds_HR>period_seconds) //MORE Than the period seconds!
  {
    // printf("HR: %d, time = %.3f\n",RR,Simulator::Now().GetSeconds());
    RR = 0;
    curr_seconds_HR = curr_seconds2;
  }
}

template<class Policy>
void
ContentStoreImpl<Policy>::RCountsTrace(Name name)
{
  RCounts[name]++;
  double curr_seconds2 = Simulator::Now().GetSeconds();
  if(curr_seconds2-curr_seconds_RCounts>period_seconds) //MORE Than the period seconds!
  {
    RCounts.clear();
    curr_seconds_RCounts = curr_seconds2;
    // double s = 0;
    //CALC S

    // printf("S: %.2f, time = %.3f\n",s,Simulator::Now().GetSeconds());
  }
}

template<class Policy>
double
ContentStoreImpl<Policy>::sheildingFunction(int t)
{
  double p=20,q=1;
  return 1.0/(1+exp((p-t)/q));
}

template<class Policy>
bool
ContentStoreImpl<Policy>::toInsert(Name name)
{
  Ptr<UniformRandomVariable> rand = CreateObject<UniformRandomVariable> ();
  rand->SetAttribute ("Min", DoubleValue (0.0));
  rand->SetAttribute ("Max", DoubleValue (1.0));

  double prob = rand->GetValue();
  // std::cout<<prob<<std::endl;
  mp_ContentsFrequency[name]++;
  if(prob<=sheildingFunction(mp_ContentsFrequency[name]))
    return true;
  return false;
}


////Lightweight////


template<class Policy>
bool
ContentStoreImpl<Policy>::populateS(Name name)
{
  if(s.size()>=s_size)
    return true;
  if(s.find(name)==s.end())
  {
    s.insert(name);
    co_count[name]=0;
    co_freq[name]=0;
  }
  return false;
}


template<class Policy>
bool
ContentStoreImpl<Policy>::attackDetection(Name name)
{
  // printf("works!!\n");
  // printf("attackDetection %d!\n",s.size());

  bool result = false;
  analyzed_cos++;
  if(s.find(name)!=s.end())//CO in S
  {
    co_count[name]++;
    // printf("trying!\n");
  }
  if(((analyzed_cos+1) % snap_size) == 0)
  {

    if(learningStep()) //learning phase is not done yet.
    {
      for (std::map<Name,int>::iterator it = co_count.begin(); it!= co_count.end(); it++)
        it->second = 0;
    }
    else //learning phase is done.
    {
      // printf("ATTACKTEST: ");

      result = attackTest();
    }
  }

  return result;
}



template<class Policy>
bool
ContentStoreImpl<Policy>::learningStep()
{

  // if(sd < mx_sd && analyzed_cos/snap_size > 20)
  ////////////????LOOOOOOOK AT THISSS
  if(analyzed_cos/snap_size > 20)
    return false;
  // printf("LEARNING: analyzed_cos = %d, snap_size = %d, Steps %.3f, sd = %.3f, mx_sd = %.3f, time = %.3f seconds\n",
      // analyzed_cos,snap_size,1.0*analyzed_cos/snap_size,sd,mx_sd, Simulator::Now().GetMinutes());

  double delta = 0;
  for (std::map<Name,double>::iterator it = co_freq.begin(); it!= co_freq.end(); it++)
  {

    double prev_co_count = it->second*(analyzed_cos-snap_size);
    double co_count_i = co_count[it->first]*1.0;
    it->second = prev_co_count + co_count_i/analyzed_cos;
    delta += (co_count_i/(snap_size-it->second));

  }
  if(k==1) //k=1, no computation needed yet
    mk=taw=delta;
  else
  {
    double mk_1 = mk; //m_(k-1) i.e. prev mk.
    mk = mk_1+(delta-mk_1)/k;
    sk = sk+(delta-mk_1)*(delta-mk);
    sd = sqrt(sk/(k-1));
    taw = mk+20*sd; ///////////////////////!!!!MAYBE WRONG, MISSING VAR VALUE!!!!!!!!!!!!!!
  }

  k++;
  return true;
}


template<class Policy>
bool
ContentStoreImpl<Policy>::attackTest()
{
  bool result = false;
  double delta = 0;
  for (std::map<Name,int>::iterator it = co_count.begin(); it!= co_count.end(); it++)
    delta += it->second*1.0/(snap_size - it->second);

  double norm = delta / taw - 1 ;
  // printf("ratio: %f , time: %.3f \n", norm, Simulator::Now().GetMinutes());
  if(delta > taw)
    result = true;

  for (std::map<Name,int>::iterator it = co_count.begin(); it!= co_count.end(); it++)
    it->second = 0;

  return result;
}


} // namespace cs
} // namespace ndn
} // namespace ns3

#endif // NDN_CONTENT_STORE_IMPL_H_
