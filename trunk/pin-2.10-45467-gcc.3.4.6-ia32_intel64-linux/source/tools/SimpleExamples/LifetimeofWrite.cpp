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
 *  This file is for evaluation for volatile PCM.
 *  It collects the basic statistics for the real trace, 
 *  and profiles the life time of each Memory Write Instruction (MWI).
 * 
 *  	First Time: during the first time running, it cannot collect all slow-write count, 
 *  since a slow-write instruction may be found to be slow later.
 *  	Second Time: by reading the slow-write instruction set from a external file, it can 
 *  completely find the slow-write instruction count.
 */


#include "pin.H"

#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
//#include "cacheHybrid.H"
#include "cacheL1.H"
#include "volatileCache.H"

#define LENGTH 7
typedef unsigned int UINT32;
/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobITraceFile(KNOB_MODE_WRITEONCE,    "pintool",
    "it", "trace", "specify the input trace file");
KNOB<string> KnobOTraceFile(KNOB_MODE_WRITEONCE,    "pintool",
    "ot", "traceIlp", "specify the output trace file");
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
    "o", "lifetime", "specify the output file");
KNOB<string> KnobGraphFile(KNOB_MODE_WRITEONCE,    "pintool",
    "og", "graph", "specify the output pair-wise graph file");
KNOB<UINT32> KnobCacheSize(KNOB_MODE_WRITEONCE, "pintool",
    "c","32", "cache size in kilobytes");
KNOB<UINT32> KnobLineSize(KNOB_MODE_WRITEONCE, "pintool",
    "b","32", "cache block size in bytes");
KNOB<UINT32> KnobAssociativity(KNOB_MODE_WRITEONCE, "pintool",
    "a","4", "cache associativity (1 for direct mapped)");
KNOB<bool> KnobEnableTrace(KNOB_MODE_WRITEONCE, "pintool",
	"t", "0", "enbale trace output");
KNOB<UINT32> KnobRetent(KNOB_MODE_WRITEONCE, "pintool",
	"r", "53000", "retention time" );
KNOB<UINT32> KnobMemLat(KNOB_MODE_WRITEONCE, "pintool",
	"m", "300", "memory latency" );
KNOB<int> KnobOptiHw(KNOB_MODE_WRITEONCE, "pintool",
	"hw", "0", "hardware optimization: full-refresh, dirty-refresh, N-refresh");
KNOB<int> KnobWriteLatency(KNOB_MODE_WRITEONCE, "pintool",
	"wl", "4", "write latency: 3,4,5,6,7,8");
KNOB<int> KnobHeadValue(KNOB_MODE_WRITEONCE, "pintool",
	"head", "400", "the head n data writes: 400, 420, 440, 460, 500");


/* ===================================================================== */
/* Global variables */
/* ===================================================================== */



//typedef UINT64 ADDRINT;
typedef int64_t INT64;

ADDRINT g_nTotalCell = 0;

ADDRINT g_nTotalWrite = 0;
ADDRINT g_nTotalRead = 0;
ADDRINT g_nTotalInst = 0;

ADDRINT g_nClockSlow = 0;
double g_nTotalEnergyFast = 0.0;
double g_nTotalEnergySlow = 0.0;

std::map<ADDRINT, UINT64> g_hLastR;
std::map<ADDRINT, UINT64> g_hLastW;
UINT64 g_Lifetime[LENGTH];

ifstream g_iTraceFile;
ofstream g_oTraceFile;

ADDRINT RefreshCycle;
UINT32 g_memoryLatency;

// latency
const ADDRINT g_rLatL1 = 2;
ADDRINT g_wLatL1 = 4;

static int g_nHead = 0;
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr <<
        "This tool represents a cache simulator.\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary() << endl; 
    return -1;
}

namespace DL1
{
    const UINT32 max_sets = 16 * KILO; // cacheSize / (lineSize * associativity);
    const UINT32 max_associativity = 16; // associativity;
    const CACHE_ALLOC::STORE_ALLOCATION allocation = CACHE_ALLOC::STORE_ALLOCATE;
	
	typedef CACHE1<CACHE_SET::Volatile_LRU_CACHE_SET<max_associativity>, max_sets, allocation> CACHE;
}

DL1::CACHE* dl1 = NULL;

namespace IL1
{
    const UINT32 max_sets = 16 * KILO; // cacheSize / (lineSize * associativity);
    const UINT32 max_associativity = 16; // associativity;
    const CACHE_ALLOC::STORE_ALLOCATION allocation = CACHE_ALLOC::STORE_ALLOCATE;
	
	typedef CACHE1<CACHE_SET::LRU_CACHE_SET<max_associativity>, max_sets, allocation> CACHE;
}

IL1::CACHE* il1 = NULL;

/* ===================================================================== */
VOID LoadInst(ADDRINT addr)
{
	//cerr << "LoadInst for " << hex << addr << ": " << ++g_testCounter << endl;

	(void)il1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_LOAD, 0);
	++ g_nTotalInst;
}
/* ===================================================================== */

VOID LoadSingle(ADDRINT addr, int nArea)
{
	//cerr << "LoadSingle for " << addr << endl;
	(void)dl1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_LOAD, nArea);
	++ g_nTotalRead;
    g_hLastR[addr] = g_CurrentCycle;
}
/* ===================================================================== */

VOID StoreSingle(ADDRINT addr, int nArea)
{	
	++ g_nTotalWrite;
	(void)dl1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_STORE, nArea);
	
	std::map<ADDRINT, UINT64>::iterator R = g_hLastR.find(addr);
	std::map<ADDRINT, UINT64>::iterator W = g_hLastW.find(addr);
	if( R != g_hLastR.end() && W != g_hLastW.end() )
	{
		INT64 interval = R->second - W->second;
		
	//	cerr << "interval = " << interval << endl;
		if( interval > 0)
		{		
			if( interval < 5000 )  // 8k
				++ g_Lifetime[0];
			else if( interval < 10000 )		//  16k
				++ g_Lifetime[1];
			else if( interval < 20000 )    // 32k
				++ g_Lifetime[2];
			else if( interval < 50000 )  // 64k
				++ g_Lifetime[3];
			else if( interval < 100000 ) // <128k
				++ g_Lifetime[4];
			else if( interval < 200000) // <256k
				++ g_Lifetime[5];
			else 
				++ g_Lifetime[6];
		}
		else		// indicates sequential writes
		{
			++ g_Lifetime[0];
		}
	}
	else if( W != g_hLastW.end() )
	{
		++ g_Lifetime[0];
	}
	
	// update the write-mark
	g_hLastW[addr] = g_CurrentCycle;	
}

VOID Image( VOID *v)
{
	int nArea = 0;     // 0 for stack, 1 for global, 2 for heap
	
	int nHead = 0;
	g_iTraceFile.open(KnobITraceFile.Value().c_str() );	
	if(!g_iTraceFile.good())
		cerr << "Failed to open " << KnobOTraceFile.Value().c_str();
	string szLine;
	while(g_iTraceFile.good())
	{
		getline(g_iTraceFile, szLine);
		if( szLine.size() < 1)
			continue;
		if( 'I' == szLine[0] )
		{
			ADDRINT addr;
			string szAddr = szLine.substr(2);
			stringstream ss(szAddr);
			ss >> addr;
			
			LoadInst(addr);			
		}
		else if( 'R' == szLine[0] || 'W' == szLine[0])
		{
			bool bRead = ('R' == szLine[0]);
			// R:S:4200208:12:14073623860994
			if( 'S' == szLine[2] )
			{
				UINT32 index1 = szLine.find(':', 4);
				string szStr = szLine.substr(4, index1-4);
				stringstream ss1(szStr);
				ADDRINT nFunc;
				ss1 >> nFunc;
				
				
				UINT32 index2 = szLine.find(':', index1+1);
				szStr=szLine.substr(index1+1, index2-index1-1);
				int disp;
				stringstream ss2(szStr);
				ss2 >> disp;
				
				szStr = szLine.substr(index2+1);
				ADDRINT addr;
				stringstream ss3(szStr);
				ss3 >> addr;
				
				if( bRead)
					LoadSingle(addr, 0);
				else
					StoreSingle(addr, 0);			
			}
			// W:G:6962120
			else if( 'G' == szLine[2])
			{
				nArea = 1;
				ADDRINT addr;
				string szAddr = szLine.substr(4);
				stringstream ss(szAddr);
				ss >> addr;
				if( bRead)
					LoadSingle(addr, nArea);	
				else
				{
					StoreSingle(addr, nArea);
					++ nHead;
					if( nHead >= g_nHead)
						break;
				}
			}
			else if( 'H' == szLine[2] )
			{
				nArea = 2;
				ADDRINT addr;
				string szAddr = szLine.substr(4);
				stringstream ss(szAddr);
				ss >> addr;
				
				if(bRead)
					LoadSingle(addr, nArea);	
				else
					StoreSingle(addr, nArea);
			}
		}
		else if( '#' == szLine[0])
		{
			stringstream ss(szLine.substr(1));
			ss >> g_EndOfImage;
		}
	}	
	g_iTraceFile.close();	
	
}
/* ===================================================================== */

VOID Fini(int code, VOID * v)
{
	// Finalize the work
	dl1->Fini();
	
	// dump baseline results
	char buf[256];
	sprintf(buf, "%u",KnobOptiHw.Value());
	
	ofstream outf;
	//string szOutFile = KnobOutputFile.Value() +"_" + buf;
	outf.open(KnobOutputFile.Value().c_str() );	
	if(!outf.good())
		cerr << "Failed to open " << KnobOutputFile.Value().c_str();
		
	outf << "#Parameters:\n";
	outf << "L1 read/write latency:\t" << g_rLatL1 << "/" << g_wLatL1 << " cycle" << endl;
	outf << "Memory read/write latency:\t" << g_memoryLatency << " cycle" << endl;
	outf << il1->StatsLong("#", CACHE_BASE::CACHE_TYPE_ICACHE);
	outf << dl1->StatsLong("#", CACHE_BASE::CACHE_TYPE_DCACHE);	
	
	// dump the interval distribution
	outf << "===============interval distribution==============" << endl;
	outf << "Total cycles\t" << g_CurrentCycle << endl;
	outf << "Total loads\t" << g_nTotalRead << endl;
	outf << "Total stores\t" << g_nTotalWrite << endl;
	outf << "Total instruction count\t" << g_nTotalInst << endl;
	 
	double dTotalInterval = 0.0;
	for( int i = 0; i < LENGTH; ++ i)
		dTotalInterval += g_Lifetime[i];
	outf << "Total intervals\t" << dTotalInterval << endl;
	outf << "[0~5000)\t" << g_Lifetime[0] << "\t" << g_Lifetime[0]/dTotalInterval << endl;
	outf << "[5000~10000)\t" << g_Lifetime[1]<< "\t" << g_Lifetime[1]/dTotalInterval<< endl;;
	outf << "[10000~20000)\t" << g_Lifetime[2]<< "\t" << g_Lifetime[2]/dTotalInterval<< endl;;
	outf << "[20000~50000)\t" << g_Lifetime[3]<< "\t" << g_Lifetime[3]/dTotalInterval<< endl;;
	outf << "[50000~100000)\t" << g_Lifetime[4]<< "\t" << g_Lifetime[4]/dTotalInterval<< endl;;
	outf << "[100000~200000)\t" << g_Lifetime[5]<< "\t" << g_Lifetime[5]/dTotalInterval<< endl;;
	outf << "[200000~)\t" << g_Lifetime[6]<< "\t" << g_Lifetime[6]/dTotalInterval<< endl;;
	outf.close();
	
	// dump pair-wise graph
	outf.open(KnobGraphFile.Value().c_str());
	outf.close();
}



/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    //PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }    
	
	g_wLatL1 = KnobWriteLatency.Value();
	dl1 = new DL1::CACHE("L1 Data Cache", 
		KnobCacheSize.Value() * KILO,
		KnobLineSize.Value(),
		KnobAssociativity.Value());
	dl1->SetLatency(g_rLatL1, g_wLatL1);
	il1 = new IL1::CACHE("L1 Instruction Cache", 
		32 * KILO, 
		64,
		4);
	il1->SetLatency(g_rLatL1,g_wLatL1);
	
	opti_hardware = KnobOptiHw.Value();
	g_BlockSize = KnobLineSize.Value();
	RefreshCycle = KnobRetent.Value()/4*4;
	g_memoryLatency = KnobMemLat.Value();
	g_nHead = KnobHeadValue.Value();
	
	for(int i=0; i < LENGTH; ++ i)
		g_Lifetime[i] = 0;
    
	Image(0);
	Fini(0,0);
	
	// 1. Collect user functions from a external file
	//GetUserFunction();
	// 2. Collect the start address of user functions
	//IMG_AddInstrumentFunction(Image, 0);
	// 3. Collect dynamic stack base address when function-calling
	// 4. Deal with each instruction	
    //INS_AddInstrumentFunction(Instruction, 0);
    //PIN_AddFiniFunction(Fini, 0);

    // Never returns

    //PIN_StartProgram();
    
    return 0;
}
/* ===================================================================== */
/* eof */
/* ===================================================================== */
