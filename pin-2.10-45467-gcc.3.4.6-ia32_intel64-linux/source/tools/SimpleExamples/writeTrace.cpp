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
#include <set>
#include <list>


struct Range
{
   string szFunc;
   ADDRINT nStart;
   ADDRINT nEnd;
};

std::ofstream ioutfile, doutfile;
ADDRINT lowAddr = 0;
ADDRINT highAddr = 0;
std::set<string> g_userFuncs;
std::list<Range> g_userRange;


KNOB<string> KnobIOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
    "oi", "icache.out", "specify icache file name");
KNOB<string> KnobDOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
    "od", "dcache.out", "specify dcache file name");
   
bool InRange(ADDRINT addr)
{
   if( addr < lowAddr || addr >= highAddr )
      return false;
   std::list<Range>::iterator ri = g_userRange.begin(), re = g_userRange.end();
   for(; ri != re; ++ ri)
   {
      if( addr >= ri->nStart && addr < ri->nEnd)
      {
         cerr << hex << "0X" << addr << " in " << ri->szFunc << "(" << ri->nStart << "," << ri->nEnd << ")\n";
         return true;
         
      }
   }
   return false;
}


VOID Image(IMG img, VOID *v)
{
   for(SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
   {
      for( RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn) )
      {
         string szFunc = RTN_Name(rtn);
         if( g_userFuncs.find(szFunc) != g_userFuncs.end() )
         {
            Range range;
            range.szFunc = szFunc;
            range.nStart = RTN_Address(rtn);
            range.nEnd = range.nStart + RTN_Size(rtn);
            g_userRange.push_back(range);
            
            if( lowAddr == 0 || lowAddr > range.nStart )
               lowAddr = range.nStart;
            if( highAddr == 0 || highAddr < range.nEnd )
               highAddr = range.nEnd;
         }
      }
   }
   /*if( IMG_IsMainExecutable(img) )
   {
      lowAddr = IMG_LowAddress(img);
      highAddr = IMG_HighAddress(img);
      cout << "\n" << hex << lowAddr << "----" << highAddr << "(" << highAddr - lowAddr << ")\n";
   }*/
}
/* ===================================================================== */

VOID LoadSingle(ADDRINT addr)
{
    // @todo we may access several cache lines for 
    // first level D-cache
   //dl1->AccessSingleLine(addr, CACHE_BASE::ACCESS_TYPE_LOAD );
   doutfile << hex << "0X" << addr << "\t" << "r\n";   
}

/* ===================================================================== */

VOID StoreSingle(ADDRINT addr)
{
    // @todo we may access several cache lines for 
    // first level D-cache
   //dl1->AccessSingleLine(addr, CACHE_BASE::ACCESS_TYPE_STORE );
   //cout << hex << "0X" << addr << "\t" << "w\n";
   doutfile << hex << "0X" << addr << "\t" << "w\n";
}

VOID AccessInstrution(ADDRINT addr)
{
   ioutfile << hex << "0X" << addr << "\n";
}

/* ===================================================================== */

VOID Instruction(INS ins, void * v)
{      
   ADDRINT insAddr = INS_Address(ins);
   
   if( !InRange(insAddr) )
      return;
   
   INS_InsertPredicatedCall(
      ins, IPOINT_BEFORE, (AFUNPTR) AccessInstrution,
      IARG_ADDRINT, insAddr,
      IARG_END);
   
    if (INS_IsMemoryRead(ins))
    {          
      INS_InsertPredicatedCall(
         ins, IPOINT_BEFORE, (AFUNPTR) LoadSingle,
         IARG_MEMORYREAD_EA,
         IARG_END);
   }
   
    if ( INS_IsMemoryWrite(ins) )
    {       
      INS_InsertPredicatedCall(
         ins, IPOINT_BEFORE,  (AFUNPTR) StoreSingle,
         IARG_MEMORYWRITE_EA,
         IARG_END);            
    }
}

VOID ReadUserFuncs()
{
/*   ifstream infile;
   infile.open(userFile.c_str());
   string szFunc;
   while(infile.good() )
   {
      infile >> szFunc;
      if( !szFunc.empty() )
         g_userFuncs.insert(szFunc);
   }*/
   
   g_userFuncs.insert("main");
   g_userFuncs.insert("Controller_step");
   g_userFuncs.insert("Controller_initialize");
   g_userFuncs.insert("rt_OneStep");
   g_userFuncs.insert("rt_MatMultRR_Dbl");
}

VOID Fini(INT32 code, VOID *v)
{
   ioutfile.close();
   doutfile.close();
}

/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
      cerr << "Init Pin error!\n";
        return -1;
    }
  
   ReadUserFuncs();
         
    ioutfile.open("icache.out", ios_base::out);
    doutfile.open("dcache.out", ios_base::out);
   IMG_AddInstrumentFunction(Image,0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */


