/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2011 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
//
// @ORIGINAL_AUTHOR: Artur Klauser
//

/*! @file
 *  This file contains a configurable cache class
 */

#ifndef PIN_CACHE_H
#define PIN_CACHE_H


#define KILO 1024
#define MEGA (KILO*KILO)
#define GIGA (KILO*MEGA)



#include <sstream>

#include <list>
#include <algorithm>
#include <map>
#include <set>

#include "cacheL1.H"

extern unsigned int g_nHeapBegin;
std::map<ADDRINT, CACHE_STATS> g_hShift;
std::set<ADDRINT> g_TagSet[3];



namespace CACHE_SET
{
/*!
 *  @brief Cache set with round robin replacement
 */
struct STTLineRecord
{
    bool m_bSwapSeq;
    int m_nSwapSeqWriteCounter;
    int m_nSwapTotalWriteCounter;     // infos for swap

    bool m_bMigFromSwap;
    int m_nMigCounter;					// infos for migration

    bool m_bDirty;			// a dirty cache line or not
    bool m_bValid;		// a valid cache line or not
	
//    bool m_bData;
};

typedef  struct STTLineRecord LineRecord;

template <UINT32 MAX_ASSOCIATIVITY = 4>
class HYBRID_LRU_SET
{
  private:
    CACHE_TAG _tags[MAX_ASSOCIATIVITY];
    UINT32 _tagsLastIndex;
    UINT32 _nextReplaceIndex;

public:
    bool m_bLocked;				// whether a cache set is locked or not
    std::list<UINT32> _tagsLRU;         // LRU list
    LineRecord _SttRecord[MAX_ASSOCIATIVITY];

  public:
    HYBRID_LRU_SET(UINT32 associativity = MAX_ASSOCIATIVITY)
      : _tagsLastIndex(associativity - 1)
    {
        ASSERTX(associativity <= MAX_ASSOCIATIVITY);
        _nextReplaceIndex = _tagsLastIndex;

        m_bLocked = false;        
    }

    VOID SetAssociativity(UINT32 associativity)
    {
        ASSERTX(associativity <= MAX_ASSOCIATIVITY);
        _tagsLastIndex = associativity - 1;
        _nextReplaceIndex = _tagsLastIndex;
		
		for (INT32 index = _tagsLastIndex; index >= 0; index--)
        {
            _tags[index] = CACHE_TAG(0);
            _SttRecord[index].m_bDirty = false;   // assume the cache line not dirty
            _SttRecord[index].m_bValid = false;   // assume the cache line is invalid

            if( index > 0 )
            {
				// initialize the LRU, index 0 for SRAM, 1--Max-1 for STT-RAM
                _tagsLRU.push_front(index);    
                _SttRecord[index].m_bSwapSeq = false;
                _SttRecord[index].m_nSwapSeqWriteCounter = 0;
                _SttRecord[index].m_nSwapTotalWriteCounter = 0;
            }
            else
            {
                _SttRecord[index].m_bMigFromSwap = false;
                _SttRecord[index].m_nMigCounter = 0;
            }
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
            if( _SttRecord[index].m_bValid && _tags[index] == tag)
            {
                lineIndex = index;
                goto end;
            }
        }
        result = false;

        end: return result;
    }

//    VOID Replace(CACHE_TAG tag)
//    {
//        // g++ -O3 too dumb to do CSE on following lines?!
//        const UINT32 index = _nextReplaceIndex;
//
//        _tags[index] = tag;
//        // condition typically faster than modulo
//        _nextReplaceIndex = (index == 0 ? _tagsLastIndex : index - 1);
//    }

    ////////
    // Four cases: 1) swap into STT; 2) SRAM_replace into STT; 3) migration into STT; 4) load STT

    UINT32 LoadSTT(CACHE_TAG tag, bool &bWriteBack, bool bData)
    {
        if (bData)
            ++ g_hShift[tag];      // recording only data rather than instructions

        // LRU, swap, valid, write back
		UINT32 lineIndex = _tagsLRU.back();
        //UINT32 lineIndex = _tagsLRU.front();
        if(_SttRecord[lineIndex].m_bDirty)
            bWriteBack = true;
        _tags[lineIndex] = tag;
		
		_tagsLRU.pop_back();
		_tagsLRU.push_back(lineIndex);

        //_tagsLRU.pop_front();
        //_tagsLRU.push_back(lineIndex);

//        _SttRecord[lineIndex].m_bData = bData;
        _SttRecord[lineIndex].m_bDirty = false;
        _SttRecord[lineIndex].m_bValid = true;
        _SttRecord[lineIndex].m_bSwapSeq = false;
        _SttRecord[lineIndex].m_nSwapSeqWriteCounter = 0;
        _SttRecord[lineIndex].m_nSwapTotalWriteCounter = 0;

        return lineIndex;
    }

    void LoadSram(CACHE_TAG tag, bool &bWriteBack, bool &bMig)
    {
        ++ g_hShift[tag];
        // migrate, valid, passive migration
        if(_SttRecord[0].m_bDirty)
        {
            Migrate( bWriteBack);           // passive migration from SRAM replacement
            bMig = true;
        }

        _tags[0] = tag;

        _SttRecord[0].m_bMigFromSwap = false;
        _SttRecord[0].m_nMigCounter = 0;
        _SttRecord[0].m_bDirty = true;     // load sram is caused by a write miss
        _SttRecord[0].m_bValid = true;
//        _SttRecord[0].m_bData = true;     // only data will load into SRAM
    }

    void Migrate( bool &bWriteBack)
    {
       // ?????????????A choice: a migration is like an most-recent read access
		UINT32 lineIndex = LoadSTT(_tags[0], bWriteBack, true);		      

        _SttRecord[lineIndex].m_bDirty = _SttRecord[0].m_bDirty;
        _SttRecord[0].m_bDirty = false;
        _SttRecord[0].m_bValid = false;
    }

    void Swap(UINT32 sttIndex, UINT32 sramIndex = 0)
    {
        ++ g_hShift[_tags[sttIndex] ];
        ++ g_hShift[_tags[0] ];

        CACHE_TAG tag = _tags[sttIndex];
        bool bDirty = _SttRecord[sttIndex].m_bDirty;

        if( !_SttRecord[0].m_bValid )
        {
            _tags[0] = tag;
//            _SttRecord[sramIndex].m_bData = true;     // only data could be swapped frome/into SRAM
            _SttRecord[0].m_bDirty = _SttRecord[sttIndex].m_bDirty;
            _SttRecord[0].m_bValid = true;
            _SttRecord[0].m_bMigFromSwap = true;
            _SttRecord[0].m_nMigCounter = 0;

//            _SttRecord[sttIndex].m_bData = false;
            _SttRecord[sttIndex].m_bDirty = false;
            _SttRecord[sttIndex].m_bValid = false;
            _SttRecord[sttIndex].m_bSwapSeq = false;
            _SttRecord[sttIndex].m_nSwapSeqWriteCounter = 0;
            _SttRecord[sttIndex].m_nSwapTotalWriteCounter = 0;
            return;
        }

        // valid, swap, migrate
        _tags[sttIndex] = _tags[0];
        _SttRecord[sttIndex].m_bDirty = _SttRecord[0].m_bDirty;
        _SttRecord[sttIndex].m_bSwapSeq = false;
		_SttRecord[sttIndex].m_bValid = true;
        _SttRecord[sttIndex].m_nSwapSeqWriteCounter = 0;
        _SttRecord[sttIndex].m_nSwapTotalWriteCounter = 0;
//        _SttRecord[sttIndex].m_bData = true;

        _tags[0] = tag;
        _SttRecord[0].m_bDirty = bDirty;
		_SttRecord[0].m_bValid = true;
        _SttRecord[0].m_bMigFromSwap = true;
        _SttRecord[0].m_nMigCounter = 0;
//        _SttRecord[sramIndex].m_bData = true;
    }

    void HitLRU(UINT32 lineIndex)
    {
        //if( _tagsLRU.back() == lineIndex )
		if( _tagsLRU.front() == lineIndex )
            return;

        std::list<UINT32>::iterator I = _tagsLRU.begin(), E = _tagsLRU.end();
        for( ; I != E; ++ I)
            if( *I == lineIndex)
                break;
        _tagsLRU.erase(I);
        //_tagsLRU.push_back(lineIndex);
		_tagsLRU.push_front(lineIndex);
    }

    UINT32 UnWriteBack()
    {
        UINT32 nNum = 0;
        for (INT32 index = _tagsLastIndex; index >= 0; index--)
            if( _SttRecord[index].m_bDirty && _SttRecord[index].m_bValid)
                ++ nNum;
        return nNum;
    }
};

} // namespace CACHE_SET


/*!
 *  @brief Stats output method
 */


/*!
 *  @brief Templated cache class with specific cache set allocation policies
 *
 *  All that remains to be done here is allocate and deallocate the right
 *  type of cache sets.
 */
template <class SET, UINT32 MAX_SETS, UINT32 STORE_ALLOCATION>
class HYBRID_CACHE : public CACHE_BASE
{
    public:

    typedef enum
    {
        LOC_STACK,
        LOC_HEAP,
        LOC_GLOBAL
    }LOCATION_TYPE;

	typedef enum
	{
		LOAD_STT,
		STORE_STT,
		LOAD_SRAM,
		STORE_SRAM
	} ACCESS_PLACE;

  private:
    SET _sets[MAX_SETS];

    CACHE_STATS _nWriteBack[3];
    CACHE_STATS _nSwap[3];
    CACHE_STATS _nMigration[3];

    CACHE_STATS _Uaccess[ACCESS_BASE::ACCESS_TYPE_NUM][HIT_MISS_NUM];
    CACHE_STATS _UnWriteBack[3];
    CACHE_STATS _UnSwap[3];
    CACHE_STATS _UnMigration[3];

    // statistics per load/write X Stt/Sram
    CACHE_STATS _AccessPlace[4];

    // statistics for each memory block (per tag)
    std::map<ADDRINT, CACHE_STATS> _hRead;
    std::map<ADDRINT, CACHE_STATS> _hWrite;
    std::map<ADDRINT, CACHE_STATS> _hHit;
    std::map<ADDRINT, CACHE_STATS> _hMiss;

private:
    CACHE_STATS UHits(ACCESS_BASE::ACCESS_TYPE accessType) const { return _Uaccess[accessType][true];}
    CACHE_STATS UMisses(ACCESS_BASE::ACCESS_TYPE accessType) const { return _Uaccess[accessType][false];}
    CACHE_STATS UAccesses(ACCESS_BASE::ACCESS_TYPE accessType) const { return UHits(accessType) + UMisses(accessType);}
    CACHE_STATS UHits() const { return _Uaccess[0][true] + _Uaccess[1][true];}
    CACHE_STATS UMisses() const { return _Uaccess[0][false] + _Uaccess[1][false];;}
    CACHE_STATS UAccesses() const { return UHits() + UMisses();}
  public:
    // constructors/destructors
    HYBRID_CACHE(std::string name, UINT32 cacheSize, UINT32 lineSize, UINT32 associativity)
      : CACHE_BASE(name, cacheSize, lineSize, associativity)
    {
        ASSERTX(NumSets() <= MAX_SETS);

        for (UINT32 i = 0; i < NumSets(); i++)
        {
            _sets[i].SetAssociativity(associativity);
			_sets[i].m_bLocked = false;
        }

        for (UINT32 accessType = 0; accessType < ACCESS_BASE::ACCESS_TYPE_NUM; accessType++)
        {
            _access[accessType][false] = 0;
            _access[accessType][true] = 0;
            _Uaccess[accessType][false] = 0;
            _Uaccess[accessType][true] = 0;
        }

        _nMigration[0] = _nMigration[1] = _nMigration[2] = 0;
        _nWriteBack[0] = _nWriteBack[1] = _nWriteBack[2] = 0;
        _nSwap[0] = _nSwap[1] = _nSwap[2] = 0;
        _UnMigration[0] = _UnMigration[1] = _UnMigration[2] = 0;
        _UnWriteBack[0] = _UnWriteBack[1] = _UnWriteBack[2] = 0;
        _UnSwap[0] = _UnSwap[1] = _UnSwap[2] = 0;

        _AccessPlace[0] = _AccessPlace[1] = _AccessPlace[2] = _AccessPlace[3] = 0;
    }

    // modifiers
    /// Cache access from addr to addr+size-1
    bool Access(ADDRINT addr, UINT32 size, ACCESS_BASE::ACCESS_TYPE accessType, bool bUser, bool bData);
    /// Cache access at addr that does not span cache lines
    bool AccessSingleLine(ADDRINT addr, ACCESS_BASE::ACCESS_TYPE accessType, bool bUser, bool bData);

    string Dump(string prefix, CACHE_TYPE cache_type);
    string StatsLong(string prefix, CACHE_TYPE cache_type) const;

    LOCATION_TYPE LocationType(const ADDRINT addr, bool bStack)
    {
        
        if( addr > (2952790016Lu) )  // assuming the stack size is limited by 256M
        {
            if( addr > (3221225472Lu) )
                cout << "\nError: address " << addr << " is out of range!\n";
            return LOC_STACK;
        }
		return LOC_GLOBAL;
/*		if (addr < g_nHeapBegin)
        {
            return LOC_GLOBAL;
        }
        else
            return LOC_HEAP;*/
    }
};


template <class SET, UINT32 MAX_SETS, UINT32 STORE_ALLOCATION>
string HYBRID_CACHE<SET,MAX_SETS,STORE_ALLOCATION>::Dump(string prefix, CACHE_BASE::CACHE_TYPE cache_type)
{
    const UINT32 headerWidth = 19;
    const UINT32 numberWidth = 12;

    UINT32 nNeedWriteBack = 0;
    for (UINT32 i = 0; i < NumSets(); i++)
        nNeedWriteBack += _sets[i].UnWriteBack();
    string out;
    out += StatsLong(prefix, cache_type );
    out += prefix + ljstr("Write-back left:      ", headerWidth) + mydecstr(nNeedWriteBack, numberWidth) + "\n";
    out += "\n";

    return out;
}




/*!
 *  @return true if all accessed cache lines hit
 */

template <class SET, UINT32 MAX_SETS, UINT32 STORE_ALLOCATION>
bool HYBRID_CACHE<SET,MAX_SETS,STORE_ALLOCATION>::Access(ADDRINT addr, UINT32 size, ACCESS_BASE::ACCESS_TYPE accessType, bool bUser, bool bData)
{
    const ADDRINT highAddr = addr + size;

    const ADDRINT lineSize = LineSize();
    const ADDRINT notLineMask = ~(lineSize - 1);
    do
    {
        AccessSingleLine(addr, accessType, bUser, bData);
        addr = (addr & notLineMask) + lineSize; // start address of the next cache line
    }
    while (addr < highAddr);

    return true;
}

/*!
 *  @return true if accessed cache line hits
 */
template <class SET, UINT32 MAX_SETS, UINT32 STORE_ALLOCATION>
bool HYBRID_CACHE<SET,MAX_SETS,STORE_ALLOCATION>::AccessSingleLine(ADDRINT addr, ACCESS_BASE::ACCESS_TYPE accessType, bool bUser, bool bData)
{
    CACHE_TAG tag;
    UINT32 setIndex;

    SplitAddress(addr, tag, setIndex);

    SET & set = _sets[setIndex];
    bool bNeedLock = false;
	
	// test if this block should be locked
	map<ADDRINT, set<int> >::iterator a2s_p = g_hFunc2Block.find(g_nCurFunc);
	if( a2s_p != g_hFunc2Block.end() )
	{
		// 1. get blockId
		CACHE_TAG ebpTag;
		UINT32 setIndexEbp;
		SplitAddress(g_nCurFunc, ebpTag, setIndexEbp);
		int blockId = ebpTag - tag;
		// 2. test if it should be locked
		set<int>::iterator s_p = a2s_p->second.find(blockId);
		if(s_p != a2s_p->second.end() )
		{
			bNeedLock = true;
		}
	}	
	

    LOCATION_TYPE locType = LocationType(addr, bUser);

    if( bData)
        g_TagSet[locType].insert(tag);

    UINT32 lineIndex = 0;
    bool hit = set.Find(tag, lineIndex);
    bool bWriteBack = false;
    ACCESS_PLACE acc_place = LOAD_STT;
    // on miss, loads always allocate, stores optionally
    if( accessType == ACCESS_BASE::ACCESS_TYPE_LOAD )
    {
        if( bData)
            ++ _hRead[tag];
        if( !hit)       // read miss: hit, valid, write back, swap
        {
            set.LoadSTT(tag, bWriteBack, bData);           

            acc_place = LOAD_STT;
        }
        else
        {
            if( lineIndex != 0)             // read hit STT-RAM: hit, LRU, swap
            {
                // 1. Swap, LRU
                set._SttRecord[lineIndex].m_bSwapSeq = false;
                set._SttRecord[lineIndex].m_nSwapSeqWriteCounter = 0;

                set.HitLRU(lineIndex);

                acc_place = LOAD_STT;
            }
            else                            // read hit SRAM: hit, mig
            {
                assert( bData);
                // only migrate for unlocked cache line
                if( !set.m_bLocked)
                {
                     // migrate
                    ++ set._SttRecord[lineIndex].m_nMigCounter;
                    if( !set._SttRecord[lineIndex].m_bMigFromSwap || set._SttRecord[lineIndex].m_nMigCounter >= 2)
                    {

                        set.Migrate(bWriteBack);
                        ++ _nMigration[locType];
#ifdef USER_PROFILING
                        if( bUser)
                            ++ _UnMigration[locType];
#endif	
                    }
                }

                acc_place = LOAD_SRAM;
            }
        }
    }
    else    // Write access
    {
        assert(bData);
        ++ _hWrite[tag];
        if( !hit)       // write miss: hit, valid
        {
            // for locked cache line
            if( set.m_bLocked )
            {
                UINT32 nLine = set.LoadSTT(tag, bWriteBack, bData);
                set._SttRecord[nLine].m_bDirty = true;

                //lineIndex = nLine;
                acc_place = STORE_STT;
            }
            else
            {
                bool bMig = false;
                set.LoadSram(tag, bWriteBack, bMig);
                if( bMig)
                {
                    ++ _nMigration[locType];
#ifdef USER_PROFILING
                    if( bUser)
                        ++ _UnMigration[locType];
#endif                
				}

                acc_place = STORE_SRAM;
            }
        }
        else     // write hit
        {
            if( lineIndex != 0)        // write hit STT-RAM: hit, valid, LRU, swap
            {
                set._SttRecord[lineIndex].m_bDirty = true;
                set.HitLRU(lineIndex);

                // only swap for non-locked cache line
                if( !set.m_bLocked)
                {
                    ++ set._SttRecord[lineIndex].m_nSwapTotalWriteCounter;
                    if( set._SttRecord[lineIndex].m_bSwapSeq )
                        ++ set._SttRecord[lineIndex].m_nSwapSeqWriteCounter;
                    else
                    {
                        set._SttRecord[lineIndex].m_nSwapSeqWriteCounter = 1;
                        set._SttRecord[lineIndex].m_bSwapSeq = true;
                    }

                    if( bNeedLock
                       || set._SttRecord[lineIndex].m_nSwapTotalWriteCounter >= 3
                       || (set._SttRecord[lineIndex].m_bSwapSeq && set._SttRecord[lineIndex].m_nSwapSeqWriteCounter >= 2) )
                    {
                        set.Swap(lineIndex);
                        ++ _nSwap[locType];
#ifdef USER_PROFILING
                        if( bUser)
                            ++ _UnSwap[locType];
#endif
                    }
                }

                acc_place = STORE_STT;
            }
            else                        // write hit SRAM: hit, valid, mig
            {
                // migration
                set._SttRecord[0].m_bDirty = true;

                -- set._SttRecord[0].m_nMigCounter;

                acc_place = STORE_SRAM;
            }
        }

        // for write request, always lock it
        if (bNeedLock)
            set.m_bLocked = true;
    }

    if( bData )
    {
        if( hit )
            ++ _hHit[tag];
        else
            ++ _hMiss[tag];

        ++ _AccessPlace[acc_place];

        // hit, write back
        ++ _access[accessType][hit];
#ifdef USER_PROFILING
        if( bUser)
            ++ _Uaccess[accessType][hit];
#endif    
	}

    if( bWriteBack)
    {
        ++ _nWriteBack[locType];
#ifdef USER_PROFILING		
        if( bUser)
            ++ _UnWriteBack[locType];
#endif	
    }

    return hit;
}


template <class SET, UINT32 MAX_SETS, UINT32 STORE_ALLOCATION>
string HYBRID_CACHE<SET,MAX_SETS,STORE_ALLOCATION>::StatsLong(string prefix, CACHE_BASE::CACHE_TYPE cache_type) const
{
    UINT32 headerWidth = 24;
    const UINT32 numberWidth = 12;

    string out;

    out += prefix + _name + ":" + "\n";

    if (cache_type != CACHE_TYPE_ICACHE) {
       for (UINT32 i = 0; i < (UINT32)ACCESS_BASE::ACCESS_TYPE_NUM; i++)
       {
           const ACCESS_BASE::ACCESS_TYPE accessType = (ACCESS_BASE::ACCESS_TYPE)i;

           std::string type(accessType == ACCESS_BASE::ACCESS_TYPE_LOAD ? "Load" : "Store");

           out += prefix + ljstr(type + "-Hits:      ", headerWidth)
           + mydecstr(Hits(accessType), numberWidth)  + ":  " +fltstr(100.0 * Hits(accessType) / Accesses(accessType), 4, 8) + "%:  "
           + mydecstr(UHits(accessType), numberWidth)  + ":  " +fltstr(100.0 * UHits(accessType) / Accesses(accessType), 4, 8)
            + "%\n";

           out += prefix + ljstr(type + "-Misses:    ", headerWidth)
                  + mydecstr(Misses(accessType), numberWidth) + ":  " +fltstr(100.0 * Misses(accessType) / Accesses(accessType), 4, 8) + "%:  "
                  + mydecstr(UMisses(accessType), numberWidth) + ":  " +fltstr(100.0 * UMisses(accessType) / Accesses(accessType), 4, 8)
                  + "%\n";

           out += prefix + ljstr(type + "-Accesses:  ", headerWidth)
                  + mydecstr(Accesses(accessType), numberWidth) + ":  " +fltstr(100.0 * Accesses(accessType) / Accesses(accessType), 4, 8) + "%:  "
                  + mydecstr(UAccesses(accessType), numberWidth) + ":  " +fltstr(100.0 * UAccesses(accessType) / Accesses(accessType), 4, 8)
                  + "%\n";

           out += prefix + "\n";
       }
    }

    out += prefix + ljstr("Total-Hits:      ", headerWidth)
           + mydecstr(Hits(), numberWidth) + ":  " +fltstr(100.0 * Hits() / Accesses(), 4, 8) + "%:  "
           + mydecstr(UHits(), numberWidth) + ":  " +fltstr(100.0 * UHits() / Accesses(), 4, 8)
           + "%\n";


    out += prefix + ljstr("Total-Misses:    ", headerWidth)
           + mydecstr(Misses(), numberWidth) + ":  " +fltstr(100.0 * Misses() / Accesses(),4, 8) + "%:  "
           + mydecstr(UMisses(), numberWidth) + ":  " +fltstr(100.0 * UMisses() / Accesses(),4, 8)
           + "%\n";

    out += prefix + ljstr("Total-Accesses:  ", headerWidth)
           + mydecstr(Accesses(), numberWidth) + ":  " +fltstr(100.0 * Accesses() / Accesses(), 4, 8) + "%:  "
           + mydecstr(UAccesses(), numberWidth) + ":  " +fltstr(100.0 * UAccesses() / Accesses(), 4, 8)
           + "%\n";

    out += "\n";
    for (int i = LOAD_STT; i <= STORE_SRAM; i++)
    {
        bool bLoad = true;;
       std::string type;
       if( i == LOAD_STT)
       {
           type = "Load-SttRam";
            bLoad = true;
       }
        else if( i == LOAD_SRAM)
        {
            type = "Load-Sram";
            bLoad = true;
        }

        else if( i == STORE_STT)
        {
            type = "Store-Sttram";
            bLoad = false;
        }

        else
        {
            type = "Store-Sram";
            bLoad = false;
        }


       out += prefix + ljstr(type + ":      ", headerWidth)
       + mydecstr(_AccessPlace[i], numberWidth)  + ":  "
       +fltstr(100.0 * _AccessPlace[i] / (bLoad? Accesses(ACCESS_BASE::ACCESS_TYPE_LOAD):Accesses(ACCESS_BASE::ACCESS_TYPE_STORE) ), 4, 8)
        + "%\n";
    }
     out += "\n";

    // swap, migration, write back
    UINT32 nTotalSwap = _nSwap[0] + _nSwap[1] + _nSwap[2];
    UINT32 nTotalMigrate = _nMigration[0] + _nMigration[1] + _nMigration[2];
    UINT32 nTotalWB = _nWriteBack[0] + _nWriteBack[1] + _nWriteBack[2];
    UINT32 UnTotalSwap = _UnSwap[0] + _UnSwap[1] + _UnSwap[2];
    UINT32 UnTotalMigrate = _UnMigration[0] + _UnMigration[1] + _UnMigration[2];
    UINT32 UnTotalWB = _UnWriteBack[0] + _UnWriteBack[1] + _UnWriteBack[2];
    out += "\n";
    for (UINT32 i = 0; i < 3 ; i++)
    {
        std::string type;
        if( i == LOC_GLOBAL )
            type = "Global";
        else if( i == LOC_STACK )
            type = "Stack";
        else
            type = "Heap";
        out += prefix + ljstr(type + "-Swap:    ", headerWidth)
                + mydecstr(_nSwap[i], numberWidth) + ":  " + fltstr(100.0 * _nSwap[i]/nTotalSwap, 4, 8) + "%:  "
                + mydecstr(_UnSwap[i], numberWidth) + ":  " + fltstr(100.0 * _UnSwap[i]/nTotalSwap, 4, 8)
                + "%\n";
    }
    out += prefix + ljstr("Total-Swap:      ", headerWidth)
        + mydecstr(nTotalSwap, numberWidth) + ":  " +fltstr(100.0, 4, 8) + "%:  "
        + mydecstr(UnTotalSwap, numberWidth) + ":  " +fltstr(100.0 * UnTotalSwap/nTotalSwap, 4, 8)
        + "%\n";
    out += "\n";

    for (UINT32 i = 0; i < 3 ; i++)
    {
        std::string type;
        if( i == LOC_GLOBAL )
            type = "Global";
        else if( i == LOC_STACK )
            type = "Stack";
        else
            type = "Heap";
        out += prefix + ljstr(type + "-Migration:    ", headerWidth)
                + mydecstr(_nMigration[i], numberWidth) + ":  " + fltstr(100.0 * _nMigration[i]/nTotalMigrate, 4, 8) + "%:  "
                + mydecstr(_UnMigration[i], numberWidth) + ":  " + fltstr(100.0 * _UnMigration[i]/nTotalMigrate, 4, 8)
                + "%\n";
    }
    out += prefix + ljstr("Total-Migrate:      ", headerWidth)
           + mydecstr(nTotalMigrate, numberWidth) + ":  " +fltstr(100.0, 4, 8) + "%:  "
           + mydecstr(UnTotalMigrate, numberWidth) + ":  " +fltstr(100.0 * UnTotalMigrate/nTotalMigrate, 4, 8)
           + "%\n";
    out += "\n";

    for (UINT32 i = 0; i < 3 ; i++)
    {
        std::string type;
        if( i == LOC_GLOBAL )
            type = "Global";
        else if( i == LOC_STACK )
            type = "Stack";
        else
            type = "Heap";
        out += prefix + ljstr(type + "-WriteBack:    ", headerWidth)
                + mydecstr(_nWriteBack[i], numberWidth) + ":  " + fltstr(100.0 * _nWriteBack[i]/nTotalWB, 4, 8) + "%:  "
                + mydecstr(_UnWriteBack[i], numberWidth) + ":  " + fltstr(100.0 * _UnWriteBack[i]/nTotalWB, 4, 8)
                + "%\n";
    }
    out += prefix + ljstr("Total-WriteBack:      ", headerWidth)
           + mydecstr(nTotalWB, numberWidth) + ":  " +fltstr(100.0, 4, 8) + "%:  "
           + mydecstr(UnTotalWB, numberWidth) + ":  " +fltstr(100.0 * UnTotalWB/nTotalWB, 4, 8)
           + "%\n";
    out += "\n";

    out += "##############################cache line level statistics############################\n";
    headerWidth = 16;

    out += ljstr("Tag-Num:    ", headerWidth) + ljstr("Tag-Read:    ", headerWidth)
    + ljstr("Tag-Write:    ", headerWidth) + ljstr("Tag-Shift:    ", headerWidth)
    +  ljstr("Tag-Hit:    ", headerWidth) + ljstr("Tag-Miss:    ", headerWidth) + "\n";

    for(int i = 0; i < 3; ++ i)
    {

        if( i == LOC_STACK)
            out += "###Stack###\n";
        else if( i == LOC_HEAP)
            out += "###Heap###\n";
        else
            out += "###Global###:\t"; //+ mydecstr(g_nHeapBegin >> 6, numberWidth) + "\n";

        std::set<ADDRINT>::iterator I = g_TagSet[i].begin(), E = g_TagSet[i].end();

        for(; I != E; ++ I)
        {
            ADDRINT tag = *I;
            std::map<ADDRINT, CACHE_STATS>::const_iterator kv = _hRead.find(tag);
            UINT64 nRead = (kv == _hRead.end()? 0: kv->second);
            kv = _hWrite.find(tag);
            UINT64 nWrite = (kv == _hWrite.end()? 0: kv->second);
            kv = g_hShift.find(tag);
            UINT64 nShift = (kv == g_hShift.end()? 0: kv->second);
            kv = _hHit.find(tag);
            UINT64 nHit = (kv == _hHit.end()? 0: kv->second);
             kv = _hMiss.find(tag);
            UINT64 nMiss = (kv == _hMiss.end()? 0: kv->second);

            out += mydecstr(*I, headerWidth) + ":" + mydecstr(nRead, headerWidth) + ":"
                + mydecstr(nWrite, headerWidth) + ":" + mydecstr(nShift, headerWidth) + ":"
                + mydecstr(nHit, headerWidth) + ":" + mydecstr(nMiss, headerWidth) + "\n";

        }
    }
    return out;
}

// define shortcuts
#define CACHE_HYBRID_LRU_SET(MAX_SETS, MAX_ASSOCIATIVITY, ALLOCATION) HYBRID_CACHE<CACHE_SET::HYBRID_LRU_SET<MAX_ASSOCIATIVITY>, MAX_SETS, ALLOCATION>
#define CACHE_LRU(MAX_SETS, MAX_ASSOCIATIVITY, ALLOCATION) CACHE1<CACHE_SET::LRU_CACHE_SET<MAX_ASSOCIATIVITY>, MAX_SETS, ALLOCATION>


#endif // PIN_CACHE_H