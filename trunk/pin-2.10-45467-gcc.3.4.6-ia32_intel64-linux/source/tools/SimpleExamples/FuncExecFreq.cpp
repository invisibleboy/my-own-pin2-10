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
 *  This file computes the execution times for each user function.
 */


#include "pin.H"

#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
using namespace std;


/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
    "o", "hybrid.out", "specify dcache file name");
KNOB<string> KnobLockFile(KNOB_MODE_WRITEONCE, "pintool",
	"lf", "lockfile", "lock file");

/* ===================================================================== */
/* Global variables */
/* ===================================================================== */
UINT32 g_nHeapBegin = 0;
ADDRINT g_nCurFunc = 0;
map<string, map<int, double> > g_UserfuncSet;
map<ADDRINT, int> g_FuncFreq;
//map<ADDRINT, set<int> > g_hFunc2Block;   // user functions, blocks to lock per function
map<ADDRINT, string> g_hAddr2Func;	// user function, start address to function
//map<ADDRINT, string> g_hFunc2Addr;
ADDRINT g_TotalInsts = 0;		// user function's ebp
ADDRINT g_MultiInsts = 0;
#ifdef USER_PROFILE
bool g_bStartSimu = false;	
#endif
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


/* ===================================================================== */
/* Helper functions                                                    */
/* ===================================================================== */
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
// get user function

void GetUserFunc()
{
	std::ifstream inf;
	double topN = 10;
	inf.open(KnobLockFile.Value().c_str());
	std::string szLine;
	std::string szFunc;
	std::stringstream ss;
	char cLine[256];	
	
	while(inf.getline(cLine, 255) )
	{
		szLine = cLine;
		if( szLine.size() < 4 )
			continue;
		if( szLine.find("##") == 0 )
		{
			szFunc = szLine.substr(2);
		}
		else 
		{	
			int nBlockID;
			double dFreq;
			
			ss.clear();
			ss << szLine;
			ss >> nBlockID;
			ss >> dFreq;
			
			if( dFreq < topN )
				continue;
			g_UserfuncSet[szFunc][nBlockID] = dFreq;
#ifdef QALI_DEBUG
			cerr << "--" << szFunc << "--" << nBlockID  << ":" << dFreq << endl;
#endif
		}
	}
	inf.close();
}

VOID Count(ADDRINT nAddr)
{
	++ g_FuncFreq[nAddr];
}

VOID IncInst()
{
	++ g_TotalInsts;
}

VOID IncMultiInst()
{
	++ g_MultiInsts;
}
/* ===================================================================== */
// get start address of each user function
VOID Image(IMG img, void *v)
{
/*	map<string, set<int> >::iterator s2s_p = g_UserfuncSet.begin(), s2s_e = g_UserfuncSet.end();
	for(; s2s_p != s2s_e; ++ s2s_p )
	{
		RTN rtn = RTN_FindByName(img, s2s_p->first.c_str());
		ADDRINT nAddr = RTN_Address(rtn);
		g_hFunc2Block[nAddr].insert(s2s_p->second.begin(), s2s_p->second.end());
		g_hAddr2Func[nAddr] = s2s_p->first;
#ifdef QALI_DEBUG
		cerr << "++++" << s2s_p->first << ":\t" <<hex << nAddr << dec << endl;
#endif*/
		//g_hFunc2Addr[s2s_p->first] = nAddr;
	//}	
}


VOID Routine(RTN rtn, void *v)
{
	const string &szName = RTN_Name(rtn); 
	map<string, map<int, double> >::iterator s2s_p = g_UserfuncSet.find(szName);
	if( s2s_p != g_UserfuncSet.end())	{
		
		// get name to address
		ADDRINT nAddr = RTN_Address(rtn);		
		g_hAddr2Func[nAddr] = s2s_p->first;
		g_FuncFreq[nAddr] = 0;
#ifdef QALI_DEBUG
		cerr << "++++" << s2s_p->first << ":\t" <<hex << nAddr << dec << endl;
#endif

		// add instrumentation code for ebp
		RTN_Open(rtn);
		RTN_InsertCall( 
			rtn, IPOINT_BEFORE, (AFUNPTR)Count,
			IARG_ADDRINT, nAddr,
			IARG_CONTEXT, IARG_END);
		RTN_Close(rtn);
	}		
}

VOID Instruction(INS ins, VOID *v)
{
	INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR) IncInst,				
				IARG_END);
				
	int single1 = 0, single2 = 0;
	if (INS_IsMemoryRead(ins))
    {
        // map sparse INS addresses to dense IDs
        const UINT32 size = INS_MemoryReadSize(ins);
        single1 = (size <= 4);		
    }
        
    if ( INS_IsMemoryWrite(ins) )
    {
        // map sparse INS addresses to dense IDs            
        const UINT32 size = INS_MemoryWriteSize(ins);
        single2 = (size <= 4);		
			
    }
	
	if( single1 || single2)
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR) IncMultiInst,				
				IARG_END);
}

/* ===================================================================== */

/* ===================================================================== */

VOID Fini(int code, VOID * v)
{

    std::ofstream out(KnobOutputFile.Value().c_str());

    // print D-cache profile
    // @todo what does this print
    
    out << "PIN:MEMLATENCIES 1.0. 0x0\n";
            
    out <<
        "#\n"
        "# Function Execution Stats\n"
        "#\n";    
    
	// handle with different N
	int arrN[] = {10,25, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
	for( int i = 0; i < 9; ++ i)
	{
		int N = arrN[i];
		
		
		out << N << ":\t";
		int dFreq = 0;
		int dFreq2 = 0;
		std::map<ADDRINT, int>::iterator i2i_p = g_FuncFreq.begin(), i2i_e = g_FuncFreq.end();
		for(; i2i_p != i2i_e; ++ i2i_p)
		{
			std::string szFunc = g_hAddr2Func[i2i_p->first];
			
			cerr << szFunc << ":\t" << i2i_p->second << endl;
			
			std::map<int, double>::iterator i2d_p = g_UserfuncSet[szFunc].begin(), i2d_e = g_UserfuncSet[szFunc].end();
			for( ; i2d_p != i2d_e; ++ i2d_p)
			{
				if( i2d_p->second < N )
					continue;
				++ dFreq;
				dFreq2 += i2i_p->second;
			}
		}
		
		out << dFreq << "/" << dFreq2 << endl;
	}
	
	out << "Total Insts:\t" << g_TotalInsts << endl;
	out << "Multi Insts:\t" << g_MultiInsts << endl;
      
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

   
    GetUserFunc();
	//IMG_AddInstrumentFunction( Image, 0);
	RTN_AddInstrumentFunction(Routine, 0);
    INS_AddInstrumentFunction(Instruction, 0);
	

	
    PIN_AddFiniFunction(Fini, 0);

    // Never returns

    PIN_StartProgram();
	
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */