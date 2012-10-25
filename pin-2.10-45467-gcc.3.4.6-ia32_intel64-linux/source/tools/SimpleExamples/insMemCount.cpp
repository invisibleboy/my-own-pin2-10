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


#include "pin.H"

#include <iostream>
#include <fstream>
#include <map>
//#include "cacheHybrid.H"

#undef USER_PROFILE
//#define USER_PROFILE

typedef unsigned int UINT32;
/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
    "o", "count.out", "specify dcache file name");


/* ===================================================================== */
/* Global variables */
/* ===================================================================== */
#ifdef USER_PROFILE
bool g_bStartSimu = false;	
#endif

//typedef ADDRINT UINT64;

ADDRINT g_nTotalWrite = 0;
ADDRINT g_nTotalRead = 0;
ADDRINT g_nTotalWrite2 = 0;
ADDRINT g_nTotalRead2 = 0;
ADDRINT g_nTotalInst = 0;

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


/* ===================================================================== */

VOID LoadMulti(UINT32 num)
{
	++ g_nTotalRead;
	g_nTotalRead2 += num;
}

/* ===================================================================== */

VOID StoreMulti(UINT32 num)
{
	++ g_nTotalWrite;
	g_nTotalWrite2 += num;
}

/* ===================================================================== */

VOID LoadSingle()
{
	++ g_nTotalRead;
}
/* ===================================================================== */

VOID StoreSingle()
{	
	++ g_nTotalWrite;
}

/* ===================================================================== */

VOID InsCount()
{
	++ g_nTotalInst;
}



/* ===================================================================== */
VOID Instruction(INS ins, void * v)
{   
    INS_InsertPredicatedCall(
	ins, IPOINT_BEFORE,  (AFUNPTR) InsCount,
	IARG_END);    

    if ( INS_IsMemoryWrite(ins) )
    {
        // map sparse INS addresses to dense IDs            
        const UINT32 size = INS_MemoryWriteSize(ins);

        UINT32 num = size/4;
	if( num < 1)
		num = 1;
	INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE,  (AFUNPTR) StoreMulti,
			IARG_UINT32, num,
			IARG_END);
	
    }
	if ( INS_IsMemoryRead(ins) )
    {
        // map sparse INS addresses to dense IDs            
        const UINT32 size = INS_MemoryReadSize(ins);

        UINT32 num = size/4;
	if( num < 1)
		num = 1;
	INS_InsertPredicatedCall(
		ins, IPOINT_BEFORE,  (AFUNPTR) LoadMulti,
		IARG_UINT32, num,
		IARG_END);

    }
}

/* ===================================================================== */

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
    
	out << "# of reads:\t" << g_nTotalRead << endl;
	out << "# of writes:\t" << g_nTotalWrite << endl;
	out << "# of reads2:\t" << g_nTotalRead << endl;
	out << "# of writes2:\t" << g_nTotalWrite << endl;
	out << "# of insts:\t" << g_nTotalInst << endl;
	
	cerr << "# of reads:\t" << g_nTotalRead << endl;
	cerr << "# of writes:\t" << g_nTotalWrite << endl;
	cerr << "# of reads2:\t" << g_nTotalRead2 << endl;
	cerr << "# of writes2:\t" << g_nTotalWrite2 << endl;
	cerr << "# of insts:\t" << g_nTotalInst << endl;
      
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
