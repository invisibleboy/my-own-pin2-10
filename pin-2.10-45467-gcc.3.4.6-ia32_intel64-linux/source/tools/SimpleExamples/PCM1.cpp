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
//const UINT64 R_fastW =  7305L;

const UINT64 R_slowW = 11158840000L;
const UINT64 C_i = 1;
const UINT64 C_r = 1;
const UINT32 C_fastW = 3;
const UINT32 C_slowW = 10;
const double E_r = 96.0;
const double E_fastW = 19.2 + 13.5*3;
const double E_slowW = 19.2 + 13.5*10;
ADDRINT g_nClock = 0;
ADDRINT g_nTotalCell = 0;

ADDRINT g_nTotalWrite = 0;
ADDRINT g_nTotalWriteL = 0;
ADDRINT g_nTotalWriteLstatic = 0;
ADDRINT g_nTotalWriteLideal = 0;
ADDRINT g_nTotalRead = 0;
ADDRINT g_nTotalInst = 0;

ADDRINT g_nTotalRefreshFast = 0;
ADDRINT g_nTotalRefreshSlow = 0;

ADDRINT g_nClockSlow = 0;
double g_nTotalEnergyFast = 0.0;
double g_nTotalEnergySlow = 0.0;
//std::map<UINT32, UINT64> g_hInterval;

std::map<ADDRINT, UINT64> g_hWriteInstL;
std::map<ADDRINT, bool> g_hWriteInstIsL;
std::map<ADDRINT, UINT64> g_hLastR;
std::map<ADDRINT, UINT64> g_hLastW;
std::map<ADDRINT, ADDRINT> g_hMem2InstW;
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

UINT32 OrderNum(ADDRINT interval)
{
	UINT32 order = -1;
	do
	{
		interval = interval >> 2;   // 4^
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
		if( g_hWriteInstL.find(lastIaddrW) != g_hWriteInstL.end() )
			++ g_hWriteInstL[lastIaddrW];
		
		
		std::map<ADDRINT, UINT64>::iterator R = g_hLastR.find(addr1);
		std::map<ADDRINT, UINT64>::iterator W = g_hLastW.find(addr1);
		if( R != g_hLastR.end() && W != g_hLastW.end() )
		{
			INT64 interval = R->second - W->second;
			
			if( interval > 0)
			{
			//	++ g_nTotalInterval;
				//UINT32 order = OrderNum(interval);
				//++ g_hInterval[order];
				
				if( ((UINT64)interval) >= R_fastW )
				{
					++ g_nTotalWriteLideal;				
				
					if( g_hWriteInstL.find(lastIaddrW) == g_hWriteInstL.end() )
						g_hWriteInstL[lastIaddrW] = 1;				
					//if(g_hWriteInstIsL[lastIaddrW] == false)
					g_hWriteInstIsL[lastIaddrW] = true;
				}
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
	if( g_hWriteInstL.find(lastIaddrW) != g_hWriteInstL.end() )
		++ g_hWriteInstL[lastIaddrW];	
	
	
	std::map<ADDRINT, UINT64>::iterator R = g_hLastR.find(addr1);
	std::map<ADDRINT, UINT64>::iterator W = g_hLastW.find(addr1);
	if( R != g_hLastR.end() && W != g_hLastW.end() )
	{
		INT64 interval = R->second - W->second;
		
	//	cerr << "interval = " << interval << endl;
		if( interval > 0)
		{		
			// ++ g_nTotalInterval;
			//UINT32 order = OrderNum(interval);
			//++ g_hInterval[order];
			
			if( ((UINT64)interval) >= R_fastW )
			{
				++ g_nTotalWriteLideal;				
				
				if( g_hWriteInstL.find(lastIaddrW) == g_hWriteInstL.end() )
					g_hWriteInstL[lastIaddrW] = 1;				
				//if(g_hWriteInstIsL[lastIaddrW] == false)
					g_hWriteInstIsL[lastIaddrW] = true;
			}
		}
		else		// indicates sequential writes
		{
			
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
VOID RefreshComputation()
{
	g_nTotalCell = g_hLastW.size();
	std::map<ADDRINT, ADDRINT>::iterator I = g_hLastW.begin(), E = g_hLastW.end();
	for(; I != E; ++ I)
	{
		UINT64 nStart = I->second;
		UINT64 nInterval = g_nClock - nStart;
		g_nTotalRefreshFast += nInterval/R_fastW;
		g_nTotalRefreshSlow += nInterval/R_slowW;
	}
	
	g_nClockSlow = g_nClock + g_nTotalWrite * (C_slowW - C_fastW);
}

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

    RefreshComputation();
	
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
	
    
    out << "PIN:MEMLATENCIES 1.0. 0x0\n";
            
    out <<
        "#\n"
        "# DCACHE stats\n"
        "#\n";    
	out << "Total memory cells:\t" << g_nTotalCell << endl;
	out << "Total Instruction:\t" << g_nTotalInst << endl;
	out << "Total Reads:\t" << g_nTotalRead << endl;
	out << "Total Writes:\t" << g_nTotalWrite << endl;    
	out << "Total fast-clock:\t" << g_nClock << endl;
	out << "Total fast refresh:\t" << g_nTotalRefreshFast << endl;
	out << "Total slow-write instruction:\t" << g_nTotalWriteL << ":\t" << g_hWriteInstL.size() << endl;
	out << "Total slow-write instruction-count:\t" << g_nTotalWriteLstatic << endl;
	out << "Total ideal slow-write inst-count:\t" << g_nTotalWriteLideal << endl;
	out << "Total slow-clock:\t" << g_nClockSlow << endl;
	out << "Total slow refresh:\t" << g_nTotalRefreshSlow << endl;
	
      
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
