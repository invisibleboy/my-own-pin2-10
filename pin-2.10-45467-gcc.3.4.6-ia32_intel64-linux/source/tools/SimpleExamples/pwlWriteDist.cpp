/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2013 Intel Corporation. All rights reserved.
 
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


#include "pin.H"

#include <iostream>
#include <fstream>
#include <set>
#include <list>
#include <map>

//#include "dcache.H"
#include "pin_profile.H"

std::ofstream g_outFile;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
    "o", "writeDist.out", "specify dcache file name");
KNOB<UINT32> KnobProfDistance(KNOB_MODE_WRITEONCE, "pintool",
    "d","10", "profing distance power: n -> 2^n");


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
/* Global Variables */
/* ===================================================================== */
typedef UINT32 ADDRT;
//typedef int64_t INT64;
std::map<ADDRINT, UINT64> g_WriteR;
std::map<ADDRINT, std::set<ADDRINT> > g_Write2Funcs;
UINT32 g_nProfDistPower = 2;
std::ofstream g_g_outFile;


UINT64 g_nFuncCount = 0;		  // unique ID for each function instance
std::list<UINT32> g_funcStack;   // tracking the function instance stack

// storage for efficiency
std::map<ADDRINT, string> g_hAddr2Func;
std::set<string> g_UserFuncs;

// switch to control the profiling
bool g_bEnable = false;



/* ===================================================================== */
VOID DumpSpace(UINT32 num)
{
	for(UINT32 i = 0; i< num; ++ i)
		cerr << ' ';
}

VOID FuncEntry(ADDRINT addr)
{
	
	
	string szFunc = g_hAddr2Func[addr];
	if( szFunc == "main")
		g_bEnable = true;
	
	if( !g_bEnable)
		return;
	
	//DumpSpace(g_funcStack.size());	
	
	++ g_nFuncCount;	
	g_funcStack.push_back(g_nFuncCount);
	
	//cerr << hex << g_funcStack.size() << "-" << (ADDRT)addr << dec << "#" << g_nFuncCount << "#" <<  szFunc << endl; 
	
}

VOID FuncExit(ADDRINT addr)
{		
	if( !g_bEnable)
		return;
	string szFunc = g_hAddr2Func[addr];
	if( szFunc == "main")
	{
		g_bEnable = false;
		//cerr << "==========ending profiling" << endl;
	}
	//DumpSpace(g_funcStack.size()-1);
	//cerr << hex << g_funcStack.size() << "-" << (ADDRT)addr << dec << "#" << g_funcStack.back() << szFunc << endl; 
	//ASSERTX(g_nFuncCount == g_funcStack.back() );
	g_funcStack.pop_back();
	
}


VOID LoadMulti(ADDRINT addr, UINT32 size)
{
   
}

/* ===================================================================== */

VOID StoreMulti(ADDRINT addr, UINT32 size)
{
	if(!g_bEnable)
		return;
    UINT32 nSize = size >> 2;
	UINT32 alignedAddr = addr >> g_nProfDistPower;
	g_WriteR[alignedAddr] += nSize;
	g_Write2Funcs[alignedAddr].insert(g_funcStack.back());
}

/* ===================================================================== */

VOID LoadSingle(ADDRINT addr)
{
   
}
/* ===================================================================== */

VOID StoreSingle(ADDRINT addr, ADDRINT iaddr)
{
	if(!g_bEnable)
		return;
	UINT32 alignedAddr = addr >> g_nProfDistPower;
    ++ g_WriteR[alignedAddr];
	g_Write2Funcs[alignedAddr].insert(g_funcStack.back());
	
}

/* ===================================================================== */


VOID Instruction(INS ins, void * v)
{
    if ( INS_IsMemoryWrite(ins) )
    {
        // map sparse INS addresses to dense IDs
        //const ADDRINT iaddr = INS_Address(ins);
            
        const UINT32 size = INS_MemoryWriteSize(ins);

        const BOOL   single = (size <= 4);
                
		if( single )
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE,  (AFUNPTR) StoreSingle,
				IARG_MEMORYWRITE_EA,
				IARG_ADDRINT, INS_Address(ins),
				IARG_END);
		}
		else
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE,  (AFUNPTR) StoreMulti,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE,
				IARG_END);
		}			
       
    }
	
	// record the count of function entry and exit via "PUSH $ebp" and "POP $ebp"
	// assume that the entry instruction will be executed once within each function instance
	if( INS_Opcode(ins) == XED_ICLASS_PUSH &&
		//INS_OperandIsReg(ins, 0) &&
		INS_OperandReg(ins, 0 ) == REG_EBP )
	{
		RTN rtn = INS_Rtn(ins);				
		ADDRINT fAddr = RTN_Address(rtn);
		
		INS_InsertPredicatedCall(
			ins, IPOINT_AFTER,  (AFUNPTR) FuncEntry,	
			IARG_ADDRINT, fAddr,
			IARG_END);		
		// collect user functions as well as their addresses
		string szFunc = RTN_Name(rtn);
		g_hAddr2Func[fAddr] = szFunc;
	}
	else if (INS_Opcode(ins) == XED_ICLASS_LEAVE )
	{
		RTN rtn = INS_Rtn(ins);			
		ADDRINT fAddr = RTN_Address(rtn);
		
		INS_InsertPredicatedCall(
			ins, IPOINT_AFTER,  (AFUNPTR) FuncExit,	
			IARG_ADDRINT, fAddr,
			IARG_END);		
	}
	else if( INS_Opcode(ins) == XED_ICLASS_POP &&
		//INS_OperandIsReg(ins, 0) &&
		INS_OperandReg(ins, 0) == REG_EBP )
	{
		RTN rtn = INS_Rtn(ins);
		ADDRINT fAddr = RTN_Address(rtn);
		INS_InsertPredicatedCall(
			ins, IPOINT_AFTER,  (AFUNPTR) FuncExit,	
			IARG_ADDRINT, fAddr,			
			IARG_END);
	}
}

/* ===================================================================== */

VOID Fini(int code, VOID * v)
{
    // print D-cache profile
    // @todo what does this print
    
    g_outFile << "PIN:MEMLATENCIES 1.0. 0x0\n";
            
    g_outFile <<
        "#\n"
        "# Write stats with cell size:\t";
	g_outFile << (1<<g_nProfDistPower);
	g_outFile <<	"\n\n";
	g_outFile << "Total function counts:\t" << g_nFuncCount << endl;
	
	std::map<ADDRINT, UINT64>::iterator i2i_p = g_WriteR.begin(), i2i_e = g_WriteR.end();
	for(; i2i_p != i2i_e; ++ i2i_p)
	{
		g_outFile << hex << "0x" << i2i_p->first << dec << "\t" << i2i_p->second << "\t" << g_Write2Funcs[i2i_p->first].size()<< endl;
	}  
    g_outFile.close();
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
	g_nProfDistPower = KnobProfDistance.Value();
	char buf[256];
    sprintf(buf, "%u",g_nProfDistPower);
    string szOutFile = KnobOutputFile.Value() +"_" + buf;

    g_outFile.open(szOutFile.c_str());

    
    
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns

    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
