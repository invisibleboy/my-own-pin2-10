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
KNOB<UINT32> KnobRetent(KNOB_MODE_WRITEONCE, "pintool",
	"r", "53000", "retention time" );
KNOB<UINT32> KnobMemLat(KNOB_MODE_WRITEONCE, "pintool",
	"m", "300", "memory latency" );
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
extern UINT32 g_BlockSize;
set<string> g_UserFuncs;
map<string, ADDRINT> g_hFuncs;
map<ADDRINT, FuncRec *> g_hFunc2Recs;
map<ADDRINT, ActiveRec *> g_hEsp2ARs;

ofstream g_traceFile;
ofstream g_outputFile;

map<ADDRINT, int> g_hFunc2Esp;
set<UINT32> g_largeFuncSet;
map<ADDRINT, UINT32> g_hCurrentFunc;

ADDRINT RefreshCycle;
UINT32 g_memoryLatency;

// latency
const ADDRINT g_rLatL1 = 2;
const ADDRINT g_wLatL1 = 4;
const ADDRINT g_rLatL2 = 200;
const ADDRINT g_wLatL2 = 200;

ADDRINT g_testCounter = 0;
// trace output
namespace Graph
{
	struct Object
	{
		int _object;
		ADDRINT _cycle;
	};
	struct Global
	{
		ADDRINT _addr;
		ADDRINT _cycle;
	};
	list<Global> g_gTrace;
	map<ADDRINT, map<ADDRINT, ADDRINT> > g_gGraph;
	map<UINT32, list<Object> > g_trace;       // function->object->cycle
	map<UINT32, map<int, map<int, ADDRINT> > > g_graph;   // function->object->object->cost
	
	void DumpGraph(ostream &os);
}


//static ADDRINT g_prevCycle = 0;

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
	//cerr << "LoadInst for " << hex << addr << ": " << ++g_testCounter << endl;

	(void)il1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_LOAD);
		
}
/* ===================================================================== */

VOID LoadSingle(ADDRINT addr)
{
	//cerr << "LoadSingle for " << addr << endl;
	(void)dl1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_LOAD);

}
/* ===================================================================== */

VOID StoreSingle(ADDRINT addr)
{	
	(void)dl1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_STORE);		
	
	if( addr < g_EndOfImage)   // track global area
	{
		//cerr << "StoreSingle for " <<dec <<  addr << "\tcycle:\t" << g_CurrentCycle << endl;
		list<Graph::Global>::iterator i_p = Graph::g_gTrace.begin(), i_e = Graph::g_gTrace.end();
		for(; i_p != i_e; ++ i_p)
		{
			ADDRINT addr1 = i_p->_addr;
			ADDRINT cycle1 = i_p->_cycle;
			if( addr1 == addr)
			{
				Graph::g_gTrace.erase(i_p);
				break;
			}
			Graph::g_gGraph[addr1][addr] += (g_CurrentCycle - cycle1 ) / RefreshCycle;
		}
		
		Graph::Global global;
		global._addr = addr;
		global._cycle = g_CurrentCycle;
		Graph::g_gTrace.push_front(global);
	}
}


/* ===================================================================== */
VOID Instruction(INS ins, void * v)
{		
	INS_InsertPredicatedCall(ins, 
				IPOINT_BEFORE,  (AFUNPTR) LoadInst, 
				IARG_ADDRINT, INS_Address(ins),
				IARG_END);
	// skip stack access here for memory access
	//if( INS_IsStackRead(ins) || INS_IsStackWrite(ins) )
		//return;   
}

void OnMemory(INS ins, void *v)
{
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

VOID StackWrite(ADDRINT addr, UINT64 nFunc, UINT32 oriDisp)
{	
	(void)dl1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_STORE);	
	
	int disp = (int) oriDisp;
	map<int, map<int, ADDRINT> > &graph = Graph::g_graph[nFunc];
	list<Graph::Object> &trace = Graph::g_trace[nFunc];
	list<Graph::Object>::iterator i_p = trace.begin(), i_e = trace.end();
	for(; i_p != i_e; ++ i_p)
	{
		if( i_p->_object == disp )
		{
			trace.erase(i_p);
			break;
		}
		
		graph[i_p->_object][disp] += (g_CurrentCycle - i_p->_cycle)/RefreshCycle;		
	}
	
	Graph::Object object;
	object._cycle = g_CurrentCycle;
	object._object = disp;
	trace.push_front(object);
}

VOID OnStackWrite(INS ins, UINT64 nFunc)
{
	ADDRINT disp = INS_MemoryDisplacement(ins);
	INS_InsertCall(ins,
		IPOINT_BEFORE, AFUNPTR(StackWrite),		
		IARG_UINT32, nFunc,
		IARG_UINT32, disp,
		//IARG_BOOL, bRead,
		//IARG_BOOL, bEsp,
		IARG_END);					
}
/* ===================================================================== */
/* get user functions' instruction-start and instruction-end addresses                                                                 */
/* ===================================================================== */
VOID Image(IMG img, VOID *v)
{
	g_EndOfImage = IMG_HighAddress(img);
	cerr << endl << "End of image:\t" << g_EndOfImage << endl;
	for( SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
	{
		for( RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn) )
		{
			RTN_Open(rtn);
			string szRtn = RTN_Name(rtn);		
			RTN_InsertCall(rtn,
				IPOINT_BEFORE,
				AFUNPTR(GetActiveRecord),							
				IARG_CONTEXT,
				IARG_END);	
			
			map<string, ADDRINT>::iterator i2s_p = g_hFuncs.find(szRtn);
			if( i2s_p != g_hFuncs.end() ) 
			{				
				//cerr << "Collect instruction address for " << hex << szRtn << endl;	
				bool bLargeFunc = false;
				// 1. track the change of stack frame by user functions, by searching "sub $24, esp"
				for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
				{
					//cout << hex << INS_Address(ins) << endl;	
					bool bTrack = false;					
					if( !bLargeFunc
						&& INS_Opcode(ins) == XED_ICLASS_SUB &&
						INS_OperandIsImmediate( ins, 1) &&
						INS_OperandIsReg( ins ,0) && 
						INS_OperandReg( ins, 0) == REG_STACK_PTR )
					{				
						// treat functions with stack less than 3x block size as small functions
						UINT32 nOffset = (UINT32) INS_OperandImmediate(ins, 1);
						//cerr << endl << "Offset:\t" << nOffset << endl;
						if( nOffset >= KnobLineSize.Value() * 1 )
						{
							//g_largeFuncSet.insert(i2s_p->second);	
							bLargeFunc = true;
						}						
					}
		
					// 2. track stack access by user functions
					// instruction accesses memory relative to ESP or EBP, the latter may be used
					// as a general register and thus mislead the judgement
					if( bLargeFunc && INS_IsStackWrite(ins) )
					{
						bool bEsp = false;
						ADDRINT disp = INS_MemoryDisplacement(ins);
						if( INS_MemoryBaseReg(ins) == REG_STACK_PTR )
							bEsp = true;
						if(disp != 0 && bEsp)
							bTrack = true;
					}
					
							
											
					// track stack write access by ESP+0x23					
					Instruction(ins, v);
					if( bTrack )
					{																			
						OnStackWrite(ins, i2s_p->second);						
					}		
					else
					{						
						OnMemory(ins, v);
					}
				}
			}
			else
			{
				for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
				{
					Instruction(ins,v);
					OnMemory(ins, v);
				}
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
	g_outputFile << "Memory read/write latency:\t" << g_memoryLatency << " cycle" << endl;
	g_outputFile << il1->StatsLong("#", CACHE_BASE::CACHE_TYPE_ICACHE);
	g_outputFile << dl1->StatsLong("#", CACHE_BASE::CACHE_TYPE_DCACHE);	
	CACHE_SET::DumpRefresh(g_outputFile);
	g_outputFile.close();
	g_traceFile.close();
	
	ofstream outf("graph");
	Graph::DumpGraph(outf);
	outf.close();
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
	
	opti_hardware = KnobOptiHw.Value();
	g_BlockSize = KnobLineSize.Value();
	RefreshCycle = KnobRetent.Value()/4*4;
	g_memoryLatency = KnobMemLat.Value();
    
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

void Graph::DumpGraph(ostream &os)
{
	os << "###0" << endl;
	map<ADDRINT, map<ADDRINT, ADDRINT> >::iterator i2i_p = g_gGraph.begin(), i2i_e = g_gGraph.end();
	for(; i2i_p != i2i_e; ++ i2i_p)
	{
		os << i2i_p->first << ":" << endl;
		map<ADDRINT, ADDRINT>::iterator i_p = i2i_p->second.begin(), i_e = i2i_p->second.end();
		int i = 0;
		for(; i_p != i_e; ++ i_p)
		{
			if( i_p->second != 0)
			{
				++ i;
				os << i_p->first << "  " << i_p->second << ";\t";
				if( i %6 == 0)
					os << endl;
			}
		}
		os << endl;
	}
	map<UINT32, map<int, map<int, ADDRINT> > >::iterator i2i2i_p = g_graph.begin(), i2i2i_e = g_graph.end();
	for(; i2i2i_p != i2i2i_e; ++ i2i2i_p)
	{
		os << "###" << i2i2i_p->first << endl;
		map<int, map<int, ADDRINT> >::iterator i2i_p = i2i2i_p->second.begin(), i2i_e = i2i2i_p->second.end();
		for(; i2i_p != i2i_e; ++ i2i_p)
		{
			os << i2i_p->first << ":" << endl;
			map<int, ADDRINT>::iterator i_p = i2i_p->second.begin(), i_e = i2i_p->second.end();
			int i = 0;
			for(; i_p != i_e; ++ i_p)
			{
				if( i_p->second != 0)
				{
					++ i;
					os << i_p->first << "  " << i_p->second << ";\t";
					if( i %6 == 0)
						os << endl;
				}
			}
			os << endl;			
		}
	}
}