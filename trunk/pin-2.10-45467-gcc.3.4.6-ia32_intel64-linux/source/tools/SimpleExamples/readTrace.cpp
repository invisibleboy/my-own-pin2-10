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
// @EXTENDED: Rodric Rabbah (rodric@gmail.com) 
//

/*! @file
 *  This file contains an ISA-portable cache simulator
 *  data cache hierarchies
 */


//#include "pin.H"

#include <iostream>
#include <fstream>
#include <set>
#include <stdlib.h>
#include "cacheL1.H"

#define CACHE_LRU(MAX_SETS, MAX_ASSOCIATIVITY, ALLOCATION) \
   CACHE1<CACHE_SET::LRU_CACHE_SET<MAX_ASSOCIATIVITY>, MAX_SETS, ALLOCATION>

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */


std::ofstream instSimFile;
std::ofstream dataSimFile;
ADDRINT lowAddr = 0, highAddr = 0;
set<string> g_userFuncs;
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr <<
        "This tool represents a cache simulator.\n"
        "\n";

    //cerr << KNOB_BASE::StringKnobSummary() << endl; 
    return -1;
}

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

// 2-way, block size of 16 bytes
// wrap configuation constants into their own name space to avoid name clashes
namespace IL1
{
    const UINT32 max_sets = KILO; // cacheSize / (lineSize * associativity);
    const UINT32 max_associativity = 256; // associativity; 
    const CACHE_ALLOC::STORE_ALLOCATION allocation = CACHE_ALLOC::STORE_ALLOCATE;

    typedef CACHE_LRU(max_sets, max_associativity, allocation) CACHE;
}

IL1::CACHE* il1 = NULL;
IL1::CACHE* il11 = NULL;

namespace DL1
{
    const UINT32 max_sets = KILO; // cacheSize / (lineSize * associativity);
    const UINT32 max_associativity = 256; // associativity;
    const CACHE_ALLOC::STORE_ALLOCATION allocation = CACHE_ALLOC::STORE_ALLOCATE;

    typedef CACHE_LRU(max_sets, max_associativity, allocation) CACHE;
}

DL1::CACHE* dl1 = NULL;
DL1::CACHE* dl11 = NULL;

typedef enum
{
    COUNTER_MISS = 0,
    COUNTER_HIT = 1,
    COUNTER_NUM
} COUNTER;

void SimInst(string szFile, int id, int nOffset)
{
   char buf[128];
   ifstream inf;
   inf.open(szFile.c_str() );
   ADDRINT addr;
   
   IL1::CACHE * il = NULL;
   if( id == 1 )
      il = il1;
   else
      il = il11;
      
   while( inf.good() )
   {      
      inf >> hex >> addr;
      //inf.getline(buf, 127);
      //sscanf(buf, "%xll", &addr);
      if( addr == 0)
         break;
      il->AccessSingleLine(addr + nOffset, CACHE_BASE::ACCESS_TYPE_LOAD);      
   }
   inf.close();
   
   instSimFile << "\n-------Simulate " << szFile << "------\n";
   il->Dump(instSimFile);
}

void SimData(string szFile, int id, int nOffset)
{
   char buf[128];
   ifstream inf;
   inf.open(szFile.c_str() );
   ADDRINT addr;
   char access;
   CACHE_BASE::ACCESS_TYPE type;
   
   DL1::CACHE * dl = NULL;
   if( id == 1 )
      dl = dl1;
   else
      dl = dl11;
   
   while( inf.good() )
   {      
      inf >> hex >> addr;
      inf >> access;
      //inf.getline(buf, 127);
      //sscanf(buf, "%xll", "%d", &addr, &access);
      
      if( access == 'r' )
         type = CACHE_BASE::ACCESS_TYPE_LOAD;
      else if( access == 'w')
         type = CACHE_BASE::ACCESS_TYPE_STORE;
      else
         break;
      dl->AccessSingleLine(addr+nOffset, type);
   }
   inf.close();
   
   dataSimFile << "\n-------Simulate " << szFile << "------\n";
   dl->Dump(dataSimFile);
}

// C1C1C1 C2C2C2 C3C3C3
void SimLoop1(int nTimes)
{
   for( int i = 0; i < nTimes; ++ i)
   {
      SimInst("icache1.out", 1, 0);
      SimData("dcache1.out", 1, 0);
   }
   for( int i = 0; i < nTimes; ++ i)
   {
      SimInst("icache2.out", 1, 700);
      SimData("dcache2.out", 1, 700);
   }
   for( int i = 0; i < nTimes; ++ i)
   {
      SimInst("icache3.out", 1, 1400);
      SimData("dcache3.out", 1, 1400);
   }
}

// C1C2C3 C1C2C3 C1C2C3
void SimLoop2(int nTimes)
{
   for( int i =0 ; i < nTimes; ++ i)
   {
      SimInst("icache1.out", 1, 0 );
      SimInst("icache2.out", 1, 700 );
      SimInst("icache3.out", 1, 1400 );
      SimData("dcache1.out", 1, 0 );
      SimData("dcache2.out", 1, 700 );
      SimData("dcache3.out", 1, 1400 );
   }
}

int main(int argc, char *argv[])
{
   if( argc < 2 )
   {
      cerr << "Lack of arguments!\n";
      return -1;
   }
   
   int nTimes = atoi(argv[1]);
      
   il1 = new IL1::CACHE("L1 Instruction Cache", 
                         1 * KILO,
                         16,
                         2);
    dl1 = new DL1::CACHE("L1 Data Cache", 
                         1 * KILO,
                         16,
                         2);
   instSimFile.open("instSim.out");
   dataSimFile.open("dataSim.out");
   //SimLoop2(nTimes);   
	
   int i = 0;
   while (i < 30 )
   {
 	SimLoop1(nTimes);
       i += nTimes *3;
  }
   
   
    return 0;
}

