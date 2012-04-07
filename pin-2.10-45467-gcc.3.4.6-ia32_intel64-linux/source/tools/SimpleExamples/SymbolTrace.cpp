/*
 * This file is for generating the symbolized memory trace (currently only collecting local symbols)
 * 1. collect the user functions, and each user function's instruction-start and instruction-end addresses
 * 2. for each user instruction, compare the operand's address with the function's stack base address
 */

#include "pin.H"

#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <map>
#include <sstream>
#include "cacheL1.H"
#include "volatileCache.H"

using namespace std;

#define UINT64 ADDRINT

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobTraceFile(KNOB_MODE_WRITEONCE,    "pintool",
    "ot", "symboltrace", "specify the output trace file");
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
    "o", "stats", "specify the output stats file");
KNOB<UINT32> KnobCacheSize(KNOB_MODE_WRITEONCE, "pintool",
    "c","32", "cache size in kilobytes");
KNOB<UINT32> KnobLineSize(KNOB_MODE_WRITEONCE, "pintool",
    "b","32", "cache block size in bytes");
KNOB<UINT32> KnobAssociativity(KNOB_MODE_WRITEONCE, "pintool",
    "a","4", "cache associativity (1 for direct mapped)");
KNOB<bool> KnobEnableTrace(KNOB_MODE_WRITEONCE, "pintool",
	"t", "0", "enbale trace output");
KNOB<int> KnobOptiHw(KNOB_MODE_WRITEONCE, "pintool",
	"hw", "0", "hardware optimization: Lihai, Xieyuan, Jason");

/* ===================================================================== */
/* Data structure                                                  */
/* ===================================================================== */
typedef struct FuncRecord
{
	string _name;
	//string _image;
	ADDRINT _startAddr;
	ADDRINT _endAddr;
} FuncRec;

typedef struct ActiveRecord
{
	FuncRec *_fr;
	ADDRINT _esp;
	ADDRINT _ebp;
	ADDRINT _subValue;
	ADDRINT _func;
}ActiveRec;

/* ===================================================================== */
/* Global variables */
/* ===================================================================== */
extern ADDRINT g_EndOfImage;
extern ADDRINT g_CurrentEsp;
set<string> g_UserFuncs;
map<string, ADDRINT> g_hFuncs;
map<ADDRINT, FuncRec *> g_hFunc2Recs;
map<ADDRINT, ActiveRec *> g_hEsp2ARs;

ofstream g_traceFile;
ofstream g_outputFile;

map<ADDRINT, int> g_hFunc2Esp;

bool g_bInstrument = false;

// latency
const ADDRINT g_rLatL1 = 2;
const ADDRINT g_wLatL1 = 4;
const ADDRINT g_rLatL2 = 200;
const ADDRINT g_wLatL2 = 200;

// trace output
ADDRINT g_wL1 = 0;
ADDRINT g_wL2 = 0;
ADDRINT g_wL3 = 0;
ADDRINT g_rL1 = 0;
ADDRINT g_rL2 = 0;
ADDRINT g_rL3 = 0;

static ADDRINT g_prevCycle = 0;

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
	
	typedef CACHE1<CACHE_SET::Volatile_LRU_CACHE_SET<max_associativity>, max_sets, allocation> CACHE;
}

IL1::CACHE* il1 = NULL;


/* ===================================================================== */
VOID LoadInst(ADDRINT addr)
{
	//cerr << "LoadInst for " << hex << addr << endl;
	(void)il1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_LOAD);
	
	if( !g_bInstrument )
		return;
			
}
/* ===================================================================== */

VOID LoadSingle(ADDRINT addr)
{
	//cerr << "LoadSingle for " << addr << endl;
	(void)dl1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_LOAD);
	if( !g_bInstrument )
		return;
    
}
/* ===================================================================== */

VOID StoreSingle(ADDRINT addr)
{
	//cerr << "StoreSingle for " << addr << endl;
	(void)dl1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_STORE);	
}


/* ===================================================================== */
VOID EnableInstrument(bool bEnable)
{
	g_bInstrument = bEnable;
}

VOID Rtn(RTN rtn, void *v)
{
	RTN_Open(rtn);
	string szRtn = RTN_Name(rtn);
	if( szRtn == "main")
		RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(EnableInstrument), IARG_BOOL, true, IARG_END );
	if( szRtn == "main_ps")
		RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(EnableInstrument), IARG_BOOL, false, IARG_END );
	RTN_Close(rtn);
}

VOID Instruction(INS ins, void * v)
{			
	INS_InsertPredicatedCall(ins, 
				IPOINT_BEFORE,  (AFUNPTR) LoadInst, 
				IARG_ADDRINT, INS_Address(ins),
				IARG_END);
	//cout << hex << INS_Address(ins) << endl;
	// skip stack access here for memory access
	//if( INS_IsStackRead(ins) || INS_IsStackWrite(ins) )
		//return;
	
    if (INS_IsMemoryRead(ins))
    {
        // map sparse INS addresses to dense IDs
        //const UINT32 size = INS_MemoryReadSize(ins);      
		INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE, (AFUNPTR) LoadSingle,
			IARG_MEMORYREAD_EA,
			IARG_CONTEXT,
			IARG_END);		
    }        
    else if ( INS_IsMemoryWrite(ins) )
    {
        // map sparse INS addresses to dense IDs  
		INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE,  (AFUNPTR) StoreSingle,
			IARG_MEMORYWRITE_EA,
			IARG_CONTEXT,
			IARG_END);		
    }
}
/* ===================================================================== */
/* get user functions from a external file                                                                  */
/* ===================================================================== */

int GetUserFunction()
{
	ifstream inf;
	inf.open("userfunc");
	while(inf.good() )
	{
		string szLine;
		getline( inf, szLine);
		
		if( szLine.size() < 4 ) 
			continue;
		stringstream ss(szLine);
		
		ADDRINT nID;
		string szFunc;
		ss >> nID >> szFunc;
		cout << nID << ":" << szFunc << endl;
		
		g_hFuncs[szFunc] = nID;
		//g_UserFuncs.insert(szLine);	
		
	}
	return 0;
}

/* ===================================================================== */
/* get instruction the stack base/top address                                                                 */
/* ===================================================================== */

VOID GetActiveRecord( const CONTEXT *ctxt )
{
/*	ADDRINT nEsp = (ADDRINT)PIN_GetContextReg( ctxt, REG_STACK_PTR);
	ActiveRec *ar = new ActiveRec;
	ar->_func = nFunc;
	ar->_subValue = nOffset;
	ar->_esp = nEsp; 
	
	g_hEsp2ARs[nFunc] = ar;*/
	
	//g_hFunc2Esp[nFunc] = nOffset;
	g_CurrentEsp = (ADDRINT)PIN_GetContextReg( ctxt, REG_STACK_PTR);
}

VOID OnStackAccess(UINT64 nFunc, UINT32 disp)
{
	//cerr << "OnStackAccess for " << disp << ":esp=" << bEsp << ":func=" << nFunc << endl;
	// interval
	//if( g_bInstrument )
	//{
		//g_traceFile << "r1" << g_rL1 << ":";
		//g_traceFile << "r2" << g_rL2 << ":";
		//g_traceFile << "r3" << g_rL3 << ":";
		//g_traceFile << "w1" << g_wL1 << ":";
		//g_traceFile << "w2" << g_wL2 << ":";
		//g_traceFile << "w3" << g_wL3 << ":";	
		
		
	//}
	//else	
	if( !g_bInstrument)
	{		
		EnableInstrument(true);
	}
	g_traceFile << g_CurrentCycle - g_prevCycle  << ":";	
	// stack access	
	g_traceFile << (int)disp;	
	g_traceFile << "@" << nFunc << ";";
	
	g_prevCycle = g_CurrentCycle;
		
	//FuncRec *fr = g_hFunc2Recs[nFunc];
	//g_traceFile << fr->_name;	

}
/* ===================================================================== */
/* get user functions' instruction-start and instruction-end addresses                                                                 */
/* ===================================================================== */
VOID Image(IMG img, VOID *v)
{
	g_EndOfImage = IMG_HighAddress(img);
	for( SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
	{
		for( RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn) )
		{
			RTN_Open(rtn);
			string szRtn = RTN_Name(rtn);
			// collecting ESP value
			RTN_InsertCall(rtn,
							IPOINT_BEFORE,
							AFUNPTR(GetActiveRecord),							
							IARG_CONTEXT,
							IARG_END);
			
			map<string, ADDRINT>::iterator i2s_p = g_hFuncs.find(szRtn);
			if( i2s_p != g_hFuncs.end() && KnobEnableTrace.Value() )
			{
				FuncRec *fr = new FuncRec;
				fr->_name = szRtn;
				fr->_startAddr = RTN_Address(rtn);
				fr->_endAddr = fr->_startAddr + RTN_Size(rtn);
				

				//g_hFunc2Recs[fr->_startAddr] = fr;
				g_hFunc2Recs[i2s_p->second] = fr;
				cerr << "Collect instruction address for " << hex << fr->_name << "(0x" << fr->_startAddr;
				cerr << ",0x" << fr->_endAddr << ")" << dec << endl;
				delete fr;
				
				// 1. track the change of stack frame by user functions, by searching "sub $24, esp"
				for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
				{
					Instruction(ins, NULL);
					if( INS_Opcode(ins) == XED_ICLASS_SUB &&
						INS_OperandIsImmediate( ins, 0) &&
						INS_OperandIsReg( ins ,1) && 
						INS_OperandReg( ins, 1) == REG_STACK_PTR )
					{				
						int nOffset = (int) INS_OperandImmediate(ins, 0);
						g_hFunc2Esp[i2s_p->second] = nOffset;	
							
/*							INS_InsertCall(ins,
								AFUNCPTR(GetActiveRecord),
								IARG_UINT64, fr->_startAddr,
								IARG_UINT32, INS_OperandImmediate(ins, 0),ACCESS_BASE
								IARG_CONTEXT,
								IARG_END);*/
						
					}
					// 2. track stack access by user functions
					// instruction accesses memory relative to ESP or EBP, the latter may be used
					// as a general register and thus mislead the judgement
					if( INS_IsStackRead(ins) || INS_IsStackWrite(ins) )
					{						
						ADDRINT disp = INS_MemoryDisplacement(ins);
						bool bRead = false;
						if( INS_IsStackRead(ins) )
							bRead = true;
						bool bEsp = false;
						if( INS_MemoryBaseReg(ins) == REG_STACK_PTR )
							bEsp = true;						
											
						if(disp != 0 && bEsp)
							INS_InsertCall(ins,
								IPOINT_BEFORE, AFUNPTR(OnStackAccess),
								IARG_ADDRINT, i2s_p->second,
								IARG_UINT32, disp,
								//IARG_BOOL, bRead,
								//IARG_BOOL, bEsp,
								IARG_END);					
					}					
				}
			}
			else
			{
				for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
					Instruction(ins,v);
			}
			RTN_Close(rtn);
		}
	}
	
}

/* ===================================================================== */

VOID Fini(int code, VOID * v)
{
	// Finalize the work
	dl1->Fini();
	
	g_outputFile << "#Parameters:\n";
	g_outputFile << "L1 read/write latency:\t" << g_rLatL1 << "/" << g_wLatL1 << " cycle" << endl;
	g_outputFile << "Memory read/write latency:\t" << g_rLatL2 << "/" << g_wLatL2 << " cycle" << endl;
	g_outputFile << il1->StatsLong("#", CACHE_BASE::CACHE_TYPE_ICACHE);
	g_outputFile << dl1->StatsLong("#", CACHE_BASE::CACHE_TYPE_DCACHE);	
	CACHE_SET::DumpRefresh(g_outputFile);
	g_outputFile.close();
	g_traceFile.close();
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
	opti_hardware = KnobOptiHw.Value();
	dl1 = new DL1::CACHE("L1 Data Cache", 
		KnobCacheSize.Value() * KILO,
		KnobLineSize.Value(),
		KnobAssociativity.Value());
	dl1->SetLatency(g_rLatL1, g_wLatL1);
	il1 = new IL1::CACHE("L1 Instruction Cache", 
		KnobCacheSize.Value() * KILO, 
		KnobLineSize.Value(),
		KnobAssociativity.Value());
	il1->SetLatency(g_rLatL1,g_wLatL1);
    
	g_traceFile.open(KnobTraceFile.Value().c_str() );
	g_outputFile.open(KnobOutputFile.Value().c_str() );
	
	if(!g_traceFile.good())
		cerr << "Failed to open " << KnobTraceFile.Value().c_str();
	if(!g_outputFile.good())
		cerr << "Failed to open " << KnobOutputFile.Value().c_str();
	
	// 1. Collect user functions from a external file
	GetUserFunction();
	// 2. Collect the start address of user functions
	IMG_AddInstrumentFunction(Image, 0);
	// 3. Collect dynamic stack base address when function-calling
	// 4. Deal with each instruction	
    //INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns

    PIN_StartProgram();
	
	
    
    return 0;
}