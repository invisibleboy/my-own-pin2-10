#ifndef PIN_VOLATILE_CACHE_H
#define PIN_VOLATILE_CACHE_H

#include <list>
#include <iostream>
#include <fstream>
//#include "tool.H"

using namespace std;

const ADDRINT RefreshCycle=(53000/16*16);
ADDRINT g_CurrentCycle;
ADDRINT g_Intervals[6];
ADDRINT g_TotalRefresh;

namespace CACHE_SET
{

	void DumpRefresh(ostream &os)
	{
		os << "++++++++++++Refresh info+++++++++++++++" << endl;
		os << "Total refresh:\t" << g_TotalRefresh << endl;
		os << "Total cycles:\t" << g_CurrentCycle << endl;
		
		ADDRINT nTotal = 0;
		for( int i =0; i < 6; ++ i )
			nTotal += g_Intervals[i];
		os << "Cycle distribution:\n";
		os << "0-16k" << "\t:" << g_Intervals[0] << "\t:" << g_Intervals[0]/nTotal << endl;
		os << "0-32k" << "\t:" << g_Intervals[1] << "\t:" << g_Intervals[1]/nTotal << endl;
		os << "0-64k" << "\t:" << g_Intervals[2] << "\t:" << g_Intervals[2]/nTotal << endl;
		os << "0-128k" << "\t:" << g_Intervals[3] << "\t:" << g_Intervals[3]/nTotal << endl;
		os << "0-256k" << "\t:" << g_Intervals[4] << "\t:" << g_Intervals[4]/nTotal << endl;
		os << "0-512k" << "\t:" << g_Intervals[5] << "\t:" << g_Intervals[5]/nTotal << endl;		
	}
	
/*!
 *  @brief Cache set with Least-Recent-Use replacement
 */
template <UINT32 MAX_ASSOCIATIVITY = 4>
class Volatile_LRU_CACHE_SET
{
  private:
    CACHE_TAG _tags[MAX_ASSOCIATIVITY];
	ADDRINT _refreCount[MAX_ASSOCIATIVITY];
    UINT32 _tagsLastIndex;
    UINT32 _nextReplaceIndex;

	UINT32 _readPenalty;
	UINT32 _writePenalty;
	
    bool _bDirty[MAX_ASSOCIATIVITY];
	bool _bValid[MAX_ASSOCIATIVITY];  // to do: no need for one-level cache

  public:
  std::list<UINT32> _tagsLRU;         // LRU list
  public:
    Volatile_LRU_CACHE_SET(UINT32 associativity = MAX_ASSOCIATIVITY)
      : _tagsLastIndex(associativity - 1)
    {
        ASSERTX(associativity <= MAX_ASSOCIATIVITY);
        _nextReplaceIndex = _tagsLastIndex;
        
    }

    VOID SetAssociativity(UINT32 associativity)
    {
        ASSERTX(associativity <= MAX_ASSOCIATIVITY);
        _tagsLastIndex = associativity - 1;
        _nextReplaceIndex = _tagsLastIndex;

	for (INT32 index = _tagsLastIndex; index >= 0; index--)
        {
            _tags[index] = CACHE_TAG(0);
            _tagsLRU.push_front(index);     // initial the lru list

			_bDirty[index] = false;
			_bValid[index] = false;
        }
    }
    UINT32 GetAssociativity(UINT32 associativity) { return _tagsLastIndex + 1; }

    UINT32 Find(CACHE_TAG tag, UINT32 &lineIndex)
    {
        bool result = true;

        for (INT32 index = _tagsLastIndex; index >= 0; index--)
        {
            // this is an ugly micro-optimization, but it does cause a
            // tighter assembly loop for ARM that way ...
            if(_tags[index] == tag)
			  {
			  lineIndex = index;
			  goto end;
			  }
        }
        result = false;

        end: return result;
    }

void HitLRU(UINT32 lineIndex, bool bWrite)
{
	g_CurrentCycle += bWrite? _writePenalty: _readPenalty;
	if( bWrite )
		Refresh(lineIndex);
	
	  
	if( _tagsLRU.back() == lineIndex )
		return;			

	std::list<UINT32>::iterator I = _tagsLRU.begin(), E = _tagsLRU.end();
	for( ; I != E; ++ I)
		if( *I == lineIndex)
			break;
	_tagsLRU.erase(I);
	_tagsLRU.push_back(lineIndex);

	if (bWrite)
		_bDirty[lineIndex] = true;
}

  void Replace(CACHE_TAG tag, bool bWrite )
  {
	  g_CurrentCycle += bWrite? _writePenalty: _readPenalty;
      UINT32 lineIndex = _tagsLRU.front();
	  if( _bValid[lineIndex])
		Refresh(lineIndex);

      _tags[lineIndex] = tag;
      _tagsLRU.pop_front();
      _tagsLRU.push_back(lineIndex);
      _bDirty[lineIndex] = false;
	  _bValid[lineIndex] = true;

      if( bWrite)
         _bDirty[lineIndex] = true;
  }

  UINT32 NeedWriteback()
  {
      UINT32 lineIndex = _tagsLRU.front();
      if(_bDirty[lineIndex])
      {
          return _tags[lineIndex];
      }

      return 0;
  }
  
 void Refresh(UINT32 index)
 {
	// distribution of intervals
	ADDRINT interval = g_CurrentCycle - _refreCount[index];
	if( !(interval & 0xffffffffffffc000LL) )		//  16k
		++ g_Intervals[0];
	else if( !(interval & 0xffffffffffff8000LL ) )    // 32k
		++ g_Intervals[1];
	else if( !(interval & 0xffffffffffff0000LL) )  // 64k
		++ g_Intervals[2];
	else if( !(interval & 0xfffffffffffe0000LL) )
		++ g_Intervals[3];
	else if( !(interval & 0xfffffffffffc0000LL) )
		++ g_Intervals[4];
	else 
		++ g_Intervals[5];
		
	// number of refreshing
	ADDRINT nRefresh = interval/RefreshCycle;
	g_TotalRefresh += nRefresh;
	
	// reset the counter
	_refreCount[index] = g_CurrentCycle;
	
  }

  UINT32 GetSpot()
  {
      return _tagsLRU.back();
  }
  
  VOID Fini()
  {
	for (INT32 index = _tagsLastIndex; index >= 0; index--)
		if( _bValid[index] )
			Refresh(index);
  }
};

} // namespace CACHE_SET

// define shortcuts
#endif // PIN_VOLATILE_CACHE_H
