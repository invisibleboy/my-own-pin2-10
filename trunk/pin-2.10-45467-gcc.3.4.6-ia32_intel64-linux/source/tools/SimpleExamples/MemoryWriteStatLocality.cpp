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
 *  This file is for the volatile PCM experimental evaluation.
 *  This file is for evaluating the locality of write-mode preference:
 *  ie. do instructions close to each other prefer the same write-mode?
 */
 /*! @file
 *  This file is for the volatile PCM experimental evaluation.
 *  This file involves two-fold use: the first-time and second-time use.
 *  The first-time is to collect the raw data, as well as the the instruction addresses which involving long life time.
 *  The second-time is to collect the execution count of each long-term instruction, for overhead evaluation.
 */


#include "pin.H"

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
//#include "cacheHybrid.H"

#undef USER_PROFILE
//#define USER_PROFILE
#define SECOND_TIME

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

const UINT32 T_fastW = 3;
const UINT32 T_slowW = 10;
const double E_fastW = 0.7;
const double E_slowW = 1;
const UINT64 R_fastW = 900000L;
const UINT64 R_slowW = 11158000000L;
//typedef UINT64 ADDRINT;

ADDRINT g_nTotalWriteZero = 0;
ADDRINT g_nTotalWriteL = 0;
ADDRINT g_nTotalWrite = 0;
ADDRINT g_nTotalRead = 0;
ADDRINT g_nTotalInst = 0;
ADDRINT g_nTotalLong = 0;


map<ADDRINT, UINT64> g_hWriteInstL;
map<ADDRINT, bool> g_hWriteInstIsL;
ADDRINT g_nTotalFastRef = 0;
std::map<ADDRINT, UINT64> g_hLastW;
std::map<ADDRINT, ADDRINT> g_hMem2InstW;
std::map<ADDRINT, UINT64> g_hLastR;
ADDRINT g_nClock = 0;
ADDRINT g_nTotalInterval = 0;
std::map<UINT32, UINT64> g_hInterval;
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
	g_nTotalRead += size;
	addr = addr & 0xfffffffffffffffc;
	//cerr << "L: " << addr << "-" << g_nClock << endl;
    // first level D-cache
#ifdef USER_PROFILE
	if( g_bStartSimu)
#endif
	for(UINT32 i = 0; i < size; ++ i)
	{
		++ g_nClock;
		g_hLastR[addr+ i*4] = g_nClock;		
	}
	
}

/* ===================================================================== */

VOID StoreMulti(ADDRINT iAddr, ADDRINT addr, UINT32 size)
{
	size = size/4;
	g_nTotalWrite += size;
	addr = addr & 0xfffffffffffffffc;
#ifdef USER_PROFILE
	if( g_bStartSimu)
#endif
	


    for( UINT32 i = 0; i < size; ++ i)
	{		
		g_nClock += T_fastW;
		ADDRINT addr1 = addr + (i << 2);
		
		std::map<ADDRINT, ADDRINT>::iterator flagP = g_hMem2InstW.find(addr1);
		if( flagP == g_hMem2InstW.end() )    // if no previous write, update write-mark and skip it
		{
			// update the write-mark
			g_hLastW[addr1] = g_nClock;
			g_hMem2InstW[addr1] = iAddr;
			return;
		}
		ADDRINT lastIaddrW = flagP->second;
	
		if( g_hWriteInstL.find(lastIaddrW) != g_hWriteInstL.end() )
			++ g_hWriteInstL[lastIaddrW];
		//cerr << "S: " << addr1 << "-" << g_nClock << endl;
		std::map<ADDRINT, UINT64>::iterator R = g_hLastR.find(addr1);
		std::map<ADDRINT, UINT64>::iterator W = g_hLastW.find(addr1);
		if( R != g_hLastR.end()  )
		{
			INT64 interval = R->second - W->second;
			
			if( interval > 0)
			{
				++ g_nTotalInterval;
				UINT32 order = OrderNum(interval,2);
				++ g_hInterval[order];
			
				if( ((UINT64)interval) >= R_fastW )
				{
					++ g_nTotalWriteL;				
					
					if( g_hWriteInstL.find(lastIaddrW) == g_hWriteInstL.end() )
						g_hWriteInstL[lastIaddrW] = 1;				
					if(g_hWriteInstIsL[lastIaddrW] == false)
						g_hWriteInstIsL[lastIaddrW] = true;
				}
			}
		}
		// write without reading it, counted as zero-life-time
		else
		{
			++ g_nTotalInterval;
			++ g_hInterval[0];
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
	addr = addr & 0xfffffffffffffffc;
	//cerr << "L: " << addr << "-" << g_nClock << endl;
	
#ifdef USER_PROFILE
	if( g_bStartSimu)
#endif
	++ g_nClock;
    g_hLastR[addr] = g_nClock;
}
/* ===================================================================== */

VOID StoreSingle(ADDRINT iAddr, ADDRINT addr)
{	
	++ g_nTotalWrite;
	g_nClock += T_fastW;
	ADDRINT addr1 = addr & 0xfffffffffffffffc;	
					
	
	//cerr << "S: " << addr << "-" << g_nClock << endl;
	std::map<ADDRINT, ADDRINT>::iterator flagP = g_hMem2InstW.find(addr1);
	if( flagP == g_hMem2InstW.end() )    // if no previous write, update write-mark and skip it
	{
		// update the write-mark
		g_hLastW[addr1] = g_nClock;
		g_hMem2InstW[addr1] = iAddr;
		return;
	}
	ADDRINT lastIaddrW = flagP->second;
	
	if( g_hWriteInstL.find(lastIaddrW) != g_hWriteInstL.end() )
		++ g_hWriteInstL[lastIaddrW];
	
	std::map<ADDRINT, UINT64>::iterator R = g_hLastR.find(addr1);
	std::map<ADDRINT, UINT64>::iterator W = g_hLastW.find(addr1);
	
	// readTime - writeTime
	if( R != g_hLastR.end() )
	{
		INT64 interval = R->second - W->second;
		
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
				if(g_hWriteInstIsL[lastIaddrW] == false)
					g_hWriteInstIsL[lastIaddrW] = true;
			}
		}
	}
	// write without reading it, counted as zero-life-time
	else 
	{
		++ g_nTotalInterval;
		++ g_hInterval[0];
	}
	// update the write-mark
	g_hLastW[addr1] = g_nClock;
	g_hMem2InstW[addr1] = iAddr;
	
}

VOID ExecInst()
{
	++ g_nTotalInst;
	++ g_nClock;
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
	//if (iaddr > 42254050)
	//{
	//	RTN rtn = INS_Rtn(ins);
	//	cout << RTN_Name(rtn) << ":\t";
	//	cout << hex << iaddr << INS_Disassemble(ins) << endl;
	//}
    if (INS_IsMemoryRead(ins))
    {
        // map sparse INS addresses to dense IDs
        const UINT32 size = INS_MemoryReadSize(ins);
        const BOOL   single = (size <= 4);
                
		if( single )
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR) LoadSingle,
				//IARG_INST_PTR,
				IARG_MEMORYREAD_EA,
				IARG_END);
		}
		else
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE,  (AFUNPTR) LoadMulti,
				//IARG_INST_PTR,
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
			g_hWriteInstIsL[iaddr] = false;
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE,  (AFUNPTR) StoreSingle,
				//IARG_INST_PTR,
				IARG_ADDRINT,	iaddr,
				IARG_MEMORYWRITE_EA,
				IARG_END);
		}
		else
		{
			 for( UINT32 i = 0; i < size; ++ i)
			{	
				ADDRINT addr1 = iaddr + (i << 2);
				g_hWriteInstIsL[addr1] = false;
			}
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE,  (AFUNPTR) StoreMulti,
				//IARG_INST_PTR,
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
	std::ifstream in("longWrite.txt");
	string szLine;
	std::istringstream iss; 
	while(getline(in,szLine))
	{
		if(szLine.size() < 6)
			continue;
		iss.str(szLine);
		ADDRINT addr;
		iss >> addr;
		g_hWriteInstL[addr]=0;
	}		
	in.close();	
}

VOID Fini(int code, VOID * v)
{

    std::ofstream out(KnobOutputFile.Value().c_str());

    // print D-cache profile
    // @todo what does this print
    
    out << "PIN:MEMLATENCIES 1.0. 0x0\n";
            
    out <<
        "#\n"
        "# DCACHE stats\n"
        "#\n";    
    
	out << "## distribution of retention time in # of memory accesses\n";
	std::map<UINT32, UINT64>::iterator I = g_hInterval.begin(), E = g_hInterval.end();
	for(; I != E; ++ I)
	{
		out << I->first << ":\t" << I->second << ":\t" << I->second/(double)g_nTotalInterval << "\n";
	}
	
	out << "###" << endl;
	out << "TotalInterval:\t" << g_nTotalInterval << endl;
	out << "TotalWrite:\t" << g_nTotalWrite << endl;
	out << "TotalWriteLong:\t" << g_nTotalWriteL << endl;
	out << "TotalWriteZero:\t" << g_hInterval[0] << endl;
	out << "TotalCycles:\t" << g_nClock << "\n";
      
	  
	// output localty info
	// 1). storing it into histogram
	std::map<UINT32, UINT32> hInterval;
	UINT count = 0;
	UINT countL = 0;
	std::map<ADDRINT, bool>::iterator K1 = g_hWriteInstIsL.begin(), K1E = g_hWriteInstIsL.end();
	for(; K1 != K1E; ++ K1)
	{
		//cerr << hex << K1->first << ":" << dec << K1->second ;
		if( !K1->second )
		{
			++ count;
		}
		else
		{
			++ countL;
			if( count != 0)
			{
				//cerr << "===" << count << endl;
				UINT32 order = OrderNum(count, 1);
				++ hInterval[order];				 
			}
			count = 0;
		}
		//cerr << endl;
	}
	
	// 2). dump locality info
	out << "#######localty info, total write insts: " << countL << " / " << g_hWriteInstIsL.size() << " ##########" << endl;
	std::map<UINT32, UINT32>::iterator K = hInterval.begin(), KE = hInterval.end();
	for(; K != KE; ++ K)
	{
		out << K->first << ":\t" << K->second << endl;
	}
    out.close();
	
	std::ofstream out1("longWrite.txt");
	std::map<ADDRINT, UINT64>::iterator J = g_hWriteInstL.begin(), JE = g_hWriteInstL.end();
	for(; J != JE; ++ J)
	{
		out1 << J->first << "\t" << J->second << endl;
	}
	
	
	
	
	
	
	out1.close();
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
  
#ifdef SECOND_TIME
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
