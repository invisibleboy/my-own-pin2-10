#ifndef PIN_VOLATILE_CACHE_H
#define PIN_VOLATILE_CACHE_H

#include <list>
#include <iostream>
#include <fstream>
//#include "tool.H"
#define LIHAI

using namespace std;

extern ADDRINT RefreshCycle;
UINT32 g_BlockSize;
ADDRINT g_CurrentCycle;
ADDRINT g_Intervals[4][7];
ADDRINT g_TotalRefresh;
ADDRINT g_EndOfImage;    // end of global area
ADDRINT g_CurrentEsp;    // begin of stack area

bool g_bEnableAll = true;
int opti_hardware = 0;

namespace CACHE_SET
{

	void DumpRefresh(ostream &os)
	{
		os << "++++++++++++Refresh info+++++++++++++++" << endl;
		os << "Refresh Cycle:\t" << RefreshCycle << endl;
		os << "Total refresh:\t" << g_TotalRefresh << endl;
		os << "Total cycles:\t" << g_CurrentCycle << endl;
		
		ADDRINT nTotal = 0;
		for( int j =0; j < 4; ++ j)
		for( int i =0; i < 6; ++ i )
			nTotal += g_Intervals[j][i];
		os << "Total intervals:\t" << nTotal << endl;
		os << "Cycle distribution of consecutive auto-refresh (write and miss-load) for blocks:\n";
		for( int j=0; j < 4; ++ j)
		{
			if( j == 0)
				os << "====Stack area" << endl;
			else if ( j== 1)
				os << "====Global area" << endl;
			else  if( j == 2)
				os << "====Heap area" << endl;
			else
				os << "====Dead block" << endl;
		os << "0-8k" << "\t:" << g_Intervals[j][0] << "\t:" << g_Intervals[j][0]/((double)nTotal) << endl;
		os << "8-16k" << "\t:" << g_Intervals[j][1] << "\t:" << g_Intervals[j][1]/((double)nTotal) << endl;
		os << "16-32k" << "\t:" << g_Intervals[j][2] << "\t:" << g_Intervals[j][2]/((double)nTotal) << endl;
		os << "32-64k" << "\t:" << g_Intervals[j][3] << "\t:" << g_Intervals[j][3]/((double)nTotal) << endl;
		os << "64-128k" << "\t:" << g_Intervals[j][4] << "\t:" << g_Intervals[j][4]/((double)nTotal) << endl;
		os << "128-256k" << "\t:" << g_Intervals[j][5] << "\t:" << g_Intervals[j][5]/((double)nTotal) << endl;
		os << "256-inf" << "\t:" << g_Intervals[j][6] << "\t:" << g_Intervals[j][6]/((double)nTotal) << endl;		
		}
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
	
	///////recording the source of the data block
	UINT32 _source[MAX_ASSOCIATIVITY];
	
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
			_refreCount[index] = 0;
        }
    }
	
	VOID SetPenalty(UINT32 rPenalty, UINT32 wPenalty)
	{
		_readPenalty = rPenalty;
		_writePenalty = wPenalty;
	}
	
    UINT32 GetAssociativity(UINT32 associativity) { return _tagsLastIndex + 1; }

    UINT32 Find(CACHE_TAG tag, UINT32 &lineIndex, int &nWriteBack)
    {
        bool result = false;
		nWriteBack = 0;
        for (INT32 index = _tagsLastIndex; index >= 0; index--)
        {
            // this is an ugly micro-optimization, but it does cause a
            // tighter assembly loop for ARM that way ...
            if(_tags[index] == tag && _bValid[index] )
			{
				nWriteBack += InValidate(index, g_bEnableAll);
				if( _bValid[index] )
				{
					lineIndex = index;
					result = true;
					break;
				}			  
			}
        }
       return result;
    }
/* switch opti_hardware
 * =0: refresh all valid blocks
 * =1: refresh all dirty blocks
 * =2: refresh limited times for dirty blocks
*/

void HitLRU(UINT32 lineIndex, bool bWrite)
{
	g_CurrentCycle += bWrite? _writePenalty: _readPenalty;
	
	if( bWrite )        
		Refresh(lineIndex, true);
	  
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

  int Replace(CACHE_TAG tag, bool bWrite, int nArea )
  {
	  g_CurrentCycle += bWrite? _writePenalty: _readPenalty;
      UINT32 lineIndex = _tagsLRU.front();
	  
	  int nWriteBack = InValidate(lineIndex, g_bEnableAll);
		  
	  if( _bValid[lineIndex])
		Refresh(lineIndex, false);
	else
		_refreCount[lineIndex] = g_CurrentCycle;

    // stack, global, heap
	_source[lineIndex] = nArea;
	
      _tags[lineIndex] = tag;
      _tagsLRU.pop_front();
      _tagsLRU.push_back(lineIndex);
      _bDirty[lineIndex] = false;
	  _bValid[lineIndex] = true;

      if( bWrite)
         _bDirty[lineIndex] = true;
	  return nWriteBack;
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
  
 int InValidate(UINT32 index, bool bEnable)
 {
	 //if( !bEnable )
	//	 return 0;
	 int nWriteBack = 0;
	 if( !_bValid[index] )
		 return nWriteBack;
	 if( opti_hardware == 0 )
		 return nWriteBack;
	 // below are valid blocks
	 ADDRINT interval = g_CurrentCycle - _refreCount[index];	 
	 if( interval < RefreshCycle )
		 return nWriteBack;
	// below are dinishing blocks
	// opti-1 invalidate non-dirty block
	if( opti_hardware == 1 && !_bDirty[index])
	{
		_bValid[index] = false;		 
		return nWriteBack;
	}
	
	// below are dirty dinishing blocks	
	// opti-2 write-back dirty block older than four-phase
	// opti-2 invalildate 2-retention-time block
	if( opti_hardware == 2 && interval >= RefreshCycle*2 )
	{
		 _bValid[index] = false;
		 g_TotalRefresh += 1;
		 if( _bDirty[index])
			nWriteBack = 1;
	}
	return nWriteBack;		 
 }
 
 void Refresh(UINT32 index, bool bIntra)
 {
	// distribution of intervals
	ADDRINT interval = g_CurrentCycle - _refreCount[index];
	int nArea = _source[index];
	if( !bIntra )
		nArea = 3;
	if( !(interval & 0xffffffffffffe000LL) )  // 8k
		++ g_Intervals[nArea][0];
	if( !(interval & 0xffffffffffffc000LL) )		//  16k
		++ g_Intervals[nArea][1];
	else if( !(interval & 0xffffffffffff8000LL ) )    // 32k
		++ g_Intervals[nArea][2];
	else if( !(interval & 0xffffffffffff0000LL) )  // 64k
		++ g_Intervals[nArea][3];
	else if( !(interval & 0xfffffffffffe0000LL) ) // <128k
		++ g_Intervals[nArea][4];
	else if( !(interval & 0xfffffffffffc0000LL) ) // <256k
		++ g_Intervals[nArea][5];
	else 
		++ g_Intervals[nArea][6];
		
		
	// number of refreshing
	ADDRINT nRefresh = interval/RefreshCycle;
	g_TotalRefresh += nRefresh;
	
	// reset the timestamps
	_refreCount[index] = g_CurrentCycle;
	
  }
  

  UINT32 GetSpot()
  {
      return _tagsLRU.back();
  }
  
  int Fini()
  {
	int nWriteback = 0;
	for (INT32 index = _tagsLastIndex; index >= 0; index--)
	{
		nWriteback += InValidate(index, true);
		if( _bValid[index] )
			Refresh(index, false);
	}
	return nWriteback;
  }
};

} // namespace CACHE_SET

// define shortcuts
#endif // PIN_VOLATILE_CACHE_H
