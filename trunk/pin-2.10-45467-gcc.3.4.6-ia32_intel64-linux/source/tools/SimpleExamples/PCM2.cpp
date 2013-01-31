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
 *  1) It collects write-energy for each 32-bit PCM block for endurance evaluation
 *  2) It collects write-interval distribution for the motivation
 *  3) It collects write-mode distribution for write-mode-selection motivation, in the Second Time
 */


#include "pin.H"

#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
//#include "cacheHybrid.H"

#define SecondTime

#undef USER_PROFILE
//#define USER_PROFILE

typedef unsigned int UINT32;
/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
    "o", "mem-write.out", "specify dcache file name");


/* ===================================================================== */
/* Global variables */
/* ===================================================================== */
#ifdef USER_PROFILE
bool g_bStartSimu = false;	
#endif



//typedef UINT64 ADDRINT;
typedef int64_t INT64;

//const UINT64 R_fastW = 1870000L;
//const UINT64 R_fastW =  935000L;
//const UINT64 R_fastW =  467500L;
//const UINT64 R_fastW =  233750L;
//const UINT64 R_fastW =  116875L;
//const UINT64 R_fastW =  58437L;
//const UINT64 R_fastW =  29218L;
const UINT64 R_fastW =  14609L;
const UINT64 R_slowW = 11158840000L;
const UINT64 C_i = 1;
const UINT64 C_r = 1;
const UINT32 C_fastW = 3;
const UINT32 C_slowW = 10;
const double E_r = 3.0*16;
const double E_fastW = (19.2 + 13.5*3)*16;
const double E_slowW = (19.2 + 7.72*10)*16;
ADDRINT g_nClock = 0;
UINT64 g_nRefresh = 0;



//std::map<UINT32, UINT64> g_hInterval;
UINT64 g_nTotalRead = 0;
UINT64 g_nTotalInst = 0;
UINT64 g_nTotalWrite = 0;
UINT64 g_nTotalWriteL;
UINT64 g_nTotalWriteLstatic;
std::map<ADDRINT, UINT64> g_hWriteInstL;
std::map<ADDRINT, bool> g_hWriteInstIsL;
std::map<ADDRINT, UINT64> g_hLastR;
std::map<ADDRINT, UINT64> g_hLastW;
std::map<ADDRINT, ADDRINT> g_hMem2InstW;

std::map<ADDRINT, UINT64> g_hFastW;  	// for 1)
std::map<ADDRINT, UINT64> g_hSlowW;
std::map<ADDRINT, UINT64> g_hIdealSlowW;
std::map<ADDRINT, UINT64> g_hIdealFastW;

UINT64 g_nTotalInterval = 0;             	// for 2)
std::map<UINT32, UINT64> g_hInterval;

UINT64	g_nFastCount = 0;					// for 3)
UINT64 g_nTotalFast = 0;
std::map<UINT32, UINT64> g_hFastCount;
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



#ifdef USER_PROFILE
void SetSimu()
{
	g_bStartSimu = true;
}
void UnsetSimu()
{
	g_bStartSimu = false;
}
#endif

UINT32 OrderNum(ADDRINT interval, UINT32 granu)
{
	if( interval == 0)
		return 0;
		
	UINT32 order = 0;
	do
	{
		interval = interval >> granu;   // 4^
		++ order;
	}while( interval > 0);
	return order;
}
/* ===================================================================== */

VOID LoadMulti(ADDRINT addr, UINT32 size)
{
	
	
	size = size/4;
	addr = addr & 0xfffffffffffffffc;
	//cerr << "L: " << addr << "-" << g_nClock << endl;
    // first level D-cache

	g_nTotalRead += size;
	g_nClock += size * C_r;
	for(UINT32 i = 0; i < size; ++ i)
	{
		
		//g_hLastR[addr+ i*4] = g_nClock;	
	}
}

/* ===================================================================== */

VOID StoreMulti(ADDRINT iAddr, ADDRINT addr, UINT32 size)
{
	size = size/4;
	addr = addr & 0xfffffffffffffffc;

	g_nTotalWrite += size;
	
    for( UINT32 i = 0; i < size; ++ i)
	{
		g_nClock += C_fastW;
		ADDRINT addr1 = addr + (i << 2);
		//cerr << "S: " << addr1 << "-" << g_nClock << endl;
		// obtain the instruction which accesses addr1 most recently
		std::map<ADDRINT, ADDRINT>::iterator flagP = g_hMem2InstW.find(addr1);
		if( flagP == g_hMem2InstW.end() )    // if no previous write, update write-mark and skip it
		{
			// update the write-mark
			g_hLastW[addr1] = g_nClock;
			g_hMem2InstW[addr1] = iAddr;
			return;
		}
		ADDRINT lastIaddrW = flagP->second;
		
		// count the execution count for each long-write instruction
		bool bSlowInst = false;
		if( g_hWriteInstL.find(lastIaddrW) != g_hWriteInstL.end() )
		{
			++ g_hWriteInstL[lastIaddrW];	
			UINT32 order = OrderNum(g_nFastCount, 1);
			++ g_hFastCount[order];
			g_nFastCount = 0;        // reset g_nFastCount
			
			bSlowInst = true;
		}
		else
		{
			++ g_nFastCount;
			++ g_nTotalFast;
		}
		
		
		std::map<ADDRINT, UINT64>::iterator R = g_hLastR.find(addr1);
		std::map<ADDRINT, UINT64>::iterator W = g_hLastW.find(addr1);
		if( R != g_hLastR.end() && W != g_hLastW.end() )
		{
			INT64 interval = R->second - W->second;
			
			std::map<ADDRINT, UINT64>::iterator fastP = g_hFastW.find( addr1);
			if( fastP == g_hFastW.end() )
			{
				g_hFastW[addr1] = 0;
				fastP = g_hFastW.find( addr1);
			}
			std::map<ADDRINT, UINT64>::iterator slowP = g_hSlowW.find( addr1);
			if( slowP == g_hSlowW.end() )
			{
				g_hSlowW[addr1] = 0;
				slowP = g_hSlowW.find( addr1);
			}
			if( bSlowInst)
				++ slowP->second;
			else
				++ fastP->second;
			std::map<ADDRINT, UINT64>::iterator ifastP = g_hIdealFastW.find( addr1);
			if( ifastP == g_hIdealFastW.end() )
			{
				g_hIdealFastW[addr1] = 0;
				ifastP = g_hIdealFastW.find( addr1);
			}
			std::map<ADDRINT, UINT64>::iterator islowP = g_hIdealSlowW.find( addr1);
			if( islowP == g_hIdealSlowW.end() )
			{
				g_hIdealSlowW[addr1] = 0;
				islowP = g_hIdealSlowW.find( addr1);
			}
			
			if( interval > 0)
			{
				++ g_nTotalInterval;
				UINT32 order = OrderNum(interval, 2);
				++ g_hInterval[order];
				
				if( ((UINT64)interval) >= R_fastW )
				{
					++ g_nTotalWriteL;				
				
					if( g_hWriteInstL.find(lastIaddrW) == g_hWriteInstL.end() )
						g_hWriteInstL[lastIaddrW] = 1;			
					g_hWriteInstIsL[lastIaddrW] = true;
					++ islowP->second;
				}
				else
					++ ifastP->second;
			}
			else
			{
				++ ifastP->second;
				++ g_nTotalInterval;
				++ g_hInterval[0];
			}
		}
		// update the write-mark
		g_hLastW[addr1] = g_nClock;
		g_hMem2InstW[addr1] = iAddr;
	}
}

/* ===================================================================== */

VOID LoadSingle(ADDRINT addr)
{
	++ g_nTotalRead;
	g_nClock += C_r;			// 1-clock per read
	addr = addr & 0xfffffffffffffffc;
	//cerr << "L: " << addr << "-" << g_nClock << endl;

    g_hLastR[addr] = g_nClock;

}
/* ===================================================================== */

VOID StoreSingle(ADDRINT iAddr, ADDRINT addr)
{	
	++ g_nTotalWrite;
	g_nClock += C_fastW;			// 3-clock per fast-write
	addr = addr & 0xfffffffffffffffc;
	//cerr << "S: " << addr << "-" << g_nClock << endl;
	ADDRINT addr1 = addr;
	
	// obtain the instruction which accesses addr1 most recently
	std::map<ADDRINT, ADDRINT>::iterator flagP = g_hMem2InstW.find(addr1);
	if( flagP == g_hMem2InstW.end() )    // if no previous write, update write-mark and skip it
	{
		// update the write-mark
		g_hLastW[addr1] = g_nClock;
		g_hMem2InstW[addr1] = iAddr;
		return;
	}
	ADDRINT lastIaddrW = flagP->second;
	
	// count the execution count for each long-write instruction
	bool bSlowInst = false;
	if( g_hWriteInstL.find(lastIaddrW) != g_hWriteInstL.end() )
	{
		++ g_hWriteInstL[lastIaddrW];	
		UINT32 order = OrderNum(g_nFastCount, 1);
		++ g_hFastCount[order];
		g_nFastCount = 0;        // reset g_nFastCount
		
		bSlowInst = true;
	}
	else
	{
		++ g_nFastCount;
		++ g_nTotalFast;
	}
	
	
	
	std::map<ADDRINT, UINT64>::iterator R = g_hLastR.find(addr1);
	std::map<ADDRINT, UINT64>::iterator W = g_hLastW.find(addr1);
	if( R != g_hLastR.end() && W != g_hLastW.end() )
	{
		INT64 interval = R->second - W->second;
		
		std::map<ADDRINT, UINT64>::iterator fastP = g_hFastW.find( addr1);
		if( fastP == g_hFastW.end() )
		{
			g_hFastW[addr1] = 0;
			fastP = g_hFastW.find( addr1);
		}
		std::map<ADDRINT, UINT64>::iterator slowP = g_hSlowW.find( addr1);
		if( slowP == g_hSlowW.end() )
		{
			g_hSlowW[addr1] = 0;
			slowP = g_hSlowW.find( addr1);
		}
		if( bSlowInst)
			++ slowP->second;
		else
			++ fastP->second;
		std::map<ADDRINT, UINT64>::iterator ifastP = g_hIdealFastW.find( addr1);
		if( ifastP == g_hIdealFastW.end() )
		{
			g_hIdealFastW[addr1] = 0;
			ifastP = g_hIdealFastW.find( addr1);
		}
		std::map<ADDRINT, UINT64>::iterator islowP = g_hIdealSlowW.find( addr1);
		if( islowP == g_hIdealSlowW.end() )
		{
			g_hIdealSlowW[addr1] = 0;
			islowP = g_hIdealSlowW.find( addr1);
		}
	
		
	//	cerr << "interval = " << interval << endl;
		if( interval > 0)
		{		
			++ g_nTotalInterval;
			UINT32 order = OrderNum(interval, 2);
			++ g_hInterval[order];
			
			if( ((UINT64)interval) >= R_fastW )
			{
				++ g_nTotalWriteL;				
				
				if( g_hWriteInstL.find(lastIaddrW) == g_hWriteInstL.end() )
					g_hWriteInstL[lastIaddrW] = 1;		
				g_hWriteInstIsL[lastIaddrW] = true;		
				
				++ islowP->second;
			}
			else
			{
				++ ifastP->second;
			}
		}
		else		// indicates sequential writes
		{
			++ ifastP->second;
			++ g_nTotalInterval;
			++ g_hInterval[0];
		}
	}
	
	// update the write-mark
	g_hLastW[addr1] = g_nClock;
	g_hMem2InstW[addr1] = iAddr;
}
/* ===================================================================== */
VOID ExecInst()
{
	++ g_nTotalInst;
	g_nClock += C_i;
}

/* ===================================================================== */
/*VOID Image(IMG img, void *v)
{
	// control the simulation 
	RTN rtn = RTN_FindByName(img, "main");
	RTN_Open(rtn);
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SetSimu, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)UnsetSimu, IARG_END);
	RTN_Close(rtn);
}*/


VOID Routine(RTN rtn, void *v)
{
#ifdef USER_PROFILE	
// control the simulation 
	string szFunc = RTN_Name(rtn);
	if(szFunc == "main")
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SetSimu, IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)UnsetSimu, IARG_END);
		RTN_Close(rtn);	
	}
#endif
}


/* ===================================================================== */
VOID Instruction(INS ins, void * v)
{
	INS_InsertPredicatedCall(
		ins, IPOINT_BEFORE, (AFUNPTR) ExecInst,
		IARG_END);
	
	ADDRINT iaddr = INS_Address(ins);
	
    if (INS_IsMemoryRead(ins))
    {
     
		// map sparse INS addresses to dense IDs
        const UINT32 size = INS_MemoryReadSize(ins);
        const BOOL   single = (size <= 4);

		if( single )
		{

			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR) LoadSingle,
				IARG_MEMORYREAD_EA,
				IARG_END);

		}
		else
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE,  (AFUNPTR) LoadMulti,
				IARG_MEMORYREAD_EA,
				IARG_MEMORYREAD_SIZE,
				IARG_END);
		}

		
    }
        
    if ( INS_IsMemoryWrite(ins) )
    {

        // map sparse INS addresses to dense IDs            
        const UINT32 size = INS_MemoryWriteSize(ins);

        const BOOL   single = (size <= 4);
		if( single )
		{

			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE,  (AFUNPTR) StoreSingle,
				IARG_ADDRINT, iaddr,
				IARG_MEMORYWRITE_EA,
				IARG_END);

		}
		else
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE,  (AFUNPTR) StoreMulti,
				IARG_ADDRINT, iaddr,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE,
				IARG_END);
		} 
	}

   
}

/* ===================================================================== */

VOID ReadLongInstAddr()
{
	char buf[256];
	sprintf(buf, "%lu", R_fastW);
	string szLogFile = KnobOutputFile.Value() + buf + "slowWrite";
	cerr << "read " << szLogFile << endl;
	std::ifstream in(szLogFile.c_str());
	string szLine;
	std::istringstream iss; 
	while(getline(in,szLine))
	{
		if(szLine.size() < 5)
			continue;
		iss.clear();
		iss.str(szLine);
		ADDRINT addr;
		iss >> addr;
		//cerr << addr << endl;
		g_hWriteInstL[addr]=0;	
	}		
	in.close();	
}

VOID Fini(int code, VOID * v)
{

	char buf[256];
	sprintf(buf, "%lu", R_fastW);
	
	string szOutFile = KnobOutputFile.Value() + buf;
    std::ofstream out(szOutFile.c_str());

    // print D-cache profile
    // @todo what does this print
	
	
	// obtain the total # of long write instruction
	g_nTotalWriteL = g_hWriteInstIsL.size();
	
	
	string szLogFile = KnobOutputFile.Value() + buf + "slowWrite";
	std::ofstream out1(szLogFile.c_str());
	std::map<ADDRINT, ADDRINT>::iterator i2i_p = g_hWriteInstL.begin(), i2i_e = g_hWriteInstL.end();
	for(; i2i_p != i2i_e; ++ i2i_p)
	{
		g_nTotalWriteLstatic += i2i_p->second;
		out1 << i2i_p->first << endl;
	}
	out1.close();
	
	// output the distribution of write-life-time
	out << "## distribution of write-life time: \t" << g_nTotalInterval << "\n";
	std::map<UINT32, UINT64>::iterator I = g_hInterval.begin(), E = g_hInterval.end();
	for(; I != E; ++ I)
	{
		out << I->first << ":\t" << I->second << ":\t" << I->second/(double)g_nTotalInterval << "\n";
	}
	
	// output the distribution of write-mode locality
	out << "## distribution of fast-write locality:\t" << g_nTotalFast << "\n";
	I = g_hFastCount.begin(), E = g_hFastCount.end();
	for(; I != E; ++ I)
	{
		out << I->first << ":\t" << I->second << ":\t" << I->second/(double)g_nTotalFast << "\n";
	}
	// output the most written PCM cell
	// 1) worst energy
	std::map<ADDRINT, double> hWriteEnergy;	
	double dWorstEnergy = 0.0;
	std::map<ADDRINT, UINT64>::iterator J = g_hFastW.begin(), JE = g_hFastW.end();
	for(; J != JE; ++ J)
		hWriteEnergy[J->first] = hWriteEnergy[J->first] + J->second * E_fastW;
	J = g_hSlowW.begin(), JE = g_hSlowW.end();
	for(; J != JE; ++ J)
		hWriteEnergy[J->first] = hWriteEnergy[J->first] + J->second * E_slowW;
	std::map<ADDRINT, double>::iterator K = hWriteEnergy.begin(), KE = hWriteEnergy.end();
	for(; K != KE; ++ K)
		if( K->second > dWorstEnergy)
			dWorstEnergy = K->second;
			
	// 2) ideally worst energy
	std::map<ADDRINT, double> hIdealWriteEnergy;	
	double dIdealWorstEnergy = 0.0;
	J = g_hIdealFastW.begin(), JE = g_hIdealFastW.end();
	for(; J != JE; ++ J)
		hIdealWriteEnergy[J->first] = hIdealWriteEnergy[J->first] + J->second * E_fastW;
	J = g_hIdealSlowW.begin(), JE = g_hIdealSlowW.end();
	for(; J != JE; ++ J)
		hIdealWriteEnergy[J->first] = hIdealWriteEnergy[J->first] + J->second * E_slowW;
	K = hIdealWriteEnergy.begin(), KE = hIdealWriteEnergy.end();
	for(; K != KE; ++ K)
		if( K->second > dIdealWorstEnergy)
			dIdealWorstEnergy = K->second;
			
	// 3) fast energy
	std::map<ADDRINT, double> hFastWriteEnergy;	
	double dFastWorstEnergy = 0.0;
	J = g_hIdealFastW.begin(), JE = g_hIdealFastW.end();
	for(; J != JE; ++ J)
		hFastWriteEnergy[J->first] = hFastWriteEnergy[J->first] + J->second * E_fastW;
	J = g_hIdealSlowW.begin(), JE = g_hIdealSlowW.end();
	for(; J != JE; ++ J)
		hFastWriteEnergy[J->first] = hFastWriteEnergy[J->first] + J->second * E_fastW;
	K = hFastWriteEnergy.begin(), KE = hFastWriteEnergy.end();
	for(; K != KE; ++ K)
		if( K->second > dFastWorstEnergy)
			dFastWorstEnergy = K->second;
			
	// 4) slow energy
	double dSlowWorstEnergy = 0.0;
	dSlowWorstEnergy = dFastWorstEnergy * (E_slowW - E_fastW);
	
	g_nRefresh = g_nClock/1870000;
	//dFastWorstEnergy = dFastWorstEnergy + g_nRefresh ()
			
			
	
    
    out << "PIN:MEMLATENCIES 1.0. 0x0\n";
            
    out <<
        "#\n"
        "# DCACHE stats\n"
        "#\n";    
	//out << "Total memory cells:\t" << g_nTotalCell << endl;
	out << "Total Instruction:\t" << g_nTotalInst << endl;
	out << "Total Reads:\t" << g_nTotalRead << endl;
	out << "Total Writes:\t" << g_nTotalWrite << endl;    
	out << "Total fast-clock:\t" << g_nClock << endl;
	out << "Total refresh:\t" << g_nRefresh << endl;
	out << "Fast Worst Energy:\t" << dFastWorstEnergy << endl;
	out << "Slow Worst Energy:\t" << dSlowWorstEnergy << endl;
	out << "Worst Write Energy:\t" << dWorstEnergy << endl;
	out << "Worst Write Energy Ideally:\t" << dIdealWorstEnergy << endl;
	//out << "Total fast refresh:\t" << g_nTotalRefreshFast << endl;
	//out << "Total slow-write instruction:\t" << g_nTotalWriteL << ":\t" << g_hWriteInstL.size() << endl;
	//out << "Total slow-write instruction-count:\t" << g_nTotalWriteLstatic << endl;
	//out << "Total slow-clock:\t" << g_nClockSlow << endl;
	//out << "Total slow refresh:\t" << g_nTotalRefreshSlow << endl;
	
      
    out.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
	
#ifdef SecondTime
	ReadLongInstAddr();
#endif
   
    
    INS_AddInstrumentFunction(Instruction, 0);
#ifdef USER_PROFILE
	RTN_AddInstrumentFunction(Routine, 0);
#endif
	//IMG_AddInstrumentFunction( Image, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns

    PIN_StartProgram();

    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
