/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013 University of California, Los Angeles
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

#include "ndn-fw-hop-count-tag.h"

namespace ns3 {
namespace ndn {

TypeId
FwHopCountTag::GetTypeId ()
{
  static TypeId tid = TypeId("ns3::ndn::FwHopCountTag")
    .SetParent<Tag>()
    .AddConstructor<FwHopCountTag>()
    ;
  return tid;
}

TypeId
FwHopCountTag::GetInstanceTypeId () const
{
  return FwHopCountTag::GetTypeId ();
}

uint32_t
FwHopCountTag::GetSerializedSize () const
{
  // +1 for m_hopCount itself
  // and +1 because the source node is not recorded as a hop
  return (2 + m_hopCount) * sizeof(uint32_t);
}

void
FwHopCountTag::Serialize (TagBuffer i) const
{
  // If this makes problems, goto src/network/model/packet-tag-list.h and increase the maximum tag
  // size (line 161).
  i.WriteU32 (m_hopCount);
  for(uint32_t n = 0; n < hops.size(); n++)
  {
    i.WriteU32 (hops[n]);
  }
}
  
void
FwHopCountTag::Deserialize (TagBuffer i)
{
  m_hopCount = i.ReadU32 ();
  hops.clear();
  for(uint32_t n = 0; n < m_hopCount + 1; n++)
  {
    hops.push_back (i.ReadU32());
  }
}

void
FwHopCountTag::Print (std::ostream &os) const
{
  os << "FwHopCountTag: " << m_hopCount << " hops [";
  for (std::vector<uint32_t>::const_reverse_iterator it = hops.rbegin(); it != hops.rend(); ++it )
  { 
      os << *it << " ";
  }
  os << "]";
}

} // namespace ndn
} // namespace ns3
