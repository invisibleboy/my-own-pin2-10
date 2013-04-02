/*
 * This file is for generating the symbolized memory trace (currently only collecting local symbols)
 * 1. collect the user functions, and each user function's instruction-start and instruction-end addresses
 * 2. for each user instruction, compare the operand's address with the function's stack base address
 * Input: the encoded trace
 * Output: the pair-wise graph, as well as the baseline results
 */

#include "pin.H"

#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <map>
#include <list>
#include <sstream>
#include "cacheL1.H"
#include "volatileCache.H"

using namespace std;

#define UINT64 ADDRINT
#define UINT32 unsigned int

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobITraceFile(KNOB_MODE_WRITEONCE,    "pintool",
    "it", "trace", "specify the input trace file");
KNOB<string> KnobOTraceFile(KNOB_MODE_WRITEONCE,    "pintool",
    "ot", "traceIlp", "specify the output trace file");
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
    "o", "statsBase", "specify the output file");
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

struct Element
{
	UINT64 _cycle;
	UINT64 _data;
	UINT32 _func;
	short   _size;
};

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

ifstream g_iTraceFile;
ofstream g_oTraceFile;

map<ADDRINT, int> g_hFunc2Esp;
set<UINT32> g_largeFuncSet;
map<ADDRINT, UINT32> g_hCurrentFunc;

ADDRINT RefreshCycle;
UINT32 g_memoryLatency;

// latency
const ADDRINT g_rLatL1 = 2;
const ADDRINT g_wLatL1 = 4;

ADDRINT g_testCounter = 0;
// trace output
namespace Graph
{
	struct Object        // store the trace for stack area
	{
		int _object;
		ADDRINT _cycle;
	};
	struct Global		// store the trace for global area
	{
		ADDRINT _addr;
		ADDRINT _cycle;
	};
	list<Global> g_gTrace;
	map<ADDRINT, map<ADDRINT, ADDRINT> > g_gGraph;
	map<UINT32, list<Object> > g_sTrace;       // function->object->cycle
	map<UINT32, map<int, map<int, ADDRINT> > > g_sGraph;   // function->object->object->cost
	
	void DumpGraph(ostream &os);
}
/////////////////////

static std::set<UINT64> g_GlobalSet;
static std::list<Element> g_GlobalTrace;
static std::map<UINT32, set<int> > g_LocalSet;
static std::map<UINT32, list<Element> > g_LocalTrace;
static std::set<UINT32> g_FuncSet;

static inline string ltstr(UINT64 val)
{
  char buf[512];
  
  sprintf(buf, "%lu", val);
  string szValue(buf);
  return szValue;
}

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

	(void)il1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_LOAD, 0);
		
}
/* ===================================================================== */

VOID LoadSingle(ADDRINT addr, int nArea)
{
	//cerr << "LoadSingle for " << addr << endl;
	(void)dl1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_LOAD, nArea);
}
/* ===================================================================== */

VOID StoreSingle(ADDRINT addr, int nArea)
{	
	(void)dl1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_STORE, nArea);
	if( addr < g_EndOfImage)   // track global area
	{
		//<cycle, data, func, bSize>
		Element elem;
		elem._cycle = g_CurrentCycle;
		elem._data = addr;
		elem._func = 1;		// "1" for the global area's function id		
		        
		
		if(g_GlobalSet.find(addr) == g_GlobalSet.end() )		
		{
			g_GlobalSet.insert(addr);
			elem._size = 4;
		}
		else
		{			
			elem._size = 0;
		}		
		g_GlobalTrace.push_back(elem);
		
			
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


VOID OnStackWrite( ADDRINT nFunc, int disp, ADDRINT addr, bool bRead)
{
	(void)dl1->AccessSingleLine(addr, ACCESS_BASE::ACCESS_TYPE_STORE, 0);		
	//<cycle, data, func, bSize>, dump the output trace file	
	
	//<cycle, data, func, bSize>
	Element elem;
	elem._cycle = g_CurrentCycle;
	elem._data = disp;
	elem._func = nFunc;		// "1" for the global area's function id		
	
	if( ((UINT32)disp + 4) >= KnobLineSize.Value() )
		g_FuncSet.insert(nFunc);
			
	std::set<int> &localSet = g_LocalSet[nFunc]; 
	if(localSet.find(disp) == localSet.end() )		
	{
		localSet.insert(disp);
		elem._size = 4;
	}
	else
	{			
		elem._size = 0;
	}		
	g_LocalTrace[nFunc].push_back(elem);
	
	// search for different data objects in the preceeding trace, and construct the pair-wise proximity graph
	map<int, map<int, ADDRINT> > &graph = Graph::g_sGraph[nFunc];
	list<Graph::Object> &trace = Graph::g_sTrace[nFunc];
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
	
	// add a new data-write object
	Graph::Object object;
	object._cycle = g_CurrentCycle;
	object._object = disp;
	trace.push_front(object);	
	
}
/* ===================================================================== */
/* get user functions' instruction-start and instruction-end addresses                                                                 */
/* ===================================================================== */
VOID Image( VOID *v)
{
	int nArea = 0;     // 0 for stack, 1 for global, 2 for heap
	
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
					OnStackWrite(nFunc, disp, addr, bRead);			
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
					StoreSingle(addr, nArea);
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
	
	// function index file <func, required blocks>
	ofstream funcFile;
	string szFile = KnobOTraceFile.Value() + "_funcs";
	funcFile.open(szFile.c_str());
	
	
	// _1 for global area trace
	szFile = KnobOTraceFile.Value() + "_" + ltstr(1);
	g_oTraceFile.open(szFile.c_str());
	g_oTraceFile << "1,0,0,0,0" << endl;
	std::list<Element>::iterator e_p = g_GlobalTrace.begin(), e_e = g_GlobalTrace.end();
	for(; e_p != e_e; ++ e_p)
	{
		g_oTraceFile << e_p->_cycle << ",";
		g_oTraceFile << e_p->_cycle << ",";
		g_oTraceFile << e_p->_data << ",";
		g_oTraceFile << e_p->_func << ",";
		g_oTraceFile << e_p->_size << endl;
	}
	g_oTraceFile << g_CurrentCycle << "," << g_CurrentCycle << ",1,0,0" << endl;
	g_oTraceFile.close();
	const int L = KnobLineSize.Value()/4;
	int nBlocks = (g_GlobalSet.size() + L-1)/L;
	funcFile << "1\t" << nBlocks << endl;
	std::string ilp2 = szFile + "_";
	g_oTraceFile.open(ilp2.c_str() );
	for(int i = 1; i <= nBlocks; ++ i)
	{
		g_oTraceFile << i << " ";
		if( i%10 == 0 )
			g_oTraceFile << endl;
	}
	g_oTraceFile.close();
	// _funcAddr for stack area trace
	std::map<UINT32, std::list<Element> >::iterator i2e_p = g_LocalTrace.begin(), i2e_e = g_LocalTrace.end();
	for(; i2e_p != i2e_e; ++ i2e_p)
	{
		UINT32 nFunc = i2e_p->first;
		if( g_FuncSet.find(nFunc) == g_FuncSet.end() )
			continue;
		if( g_LocalSet[nFunc].size() <= 1 )
			continue;		
		
		std::list<Element> &localTrace = g_LocalTrace[nFunc];		
		szFile = KnobOTraceFile.Value() + "_" + ltstr(nFunc);
		g_oTraceFile.open(szFile.c_str());
		g_oTraceFile << "1,0,0,0,0" << endl;
		e_p = localTrace.begin(), e_e = localTrace.end();
		for(; e_p != e_e; ++ e_p)
		{
			g_oTraceFile << e_p->_cycle << ",";
			g_oTraceFile << e_p->_cycle << ",";
			g_oTraceFile << e_p->_data << ",";
			g_oTraceFile << e_p->_func << ",";
			g_oTraceFile << e_p->_size << endl;
		}
		g_oTraceFile << g_CurrentCycle << "," << g_CurrentCycle << ",1,0,0" << endl;		
		g_oTraceFile.close();
		
		int nBlocks = (g_LocalSet[nFunc].size() + L-1)/L;
		funcFile << nFunc << "\t" << nBlocks << endl;
		std::string ilp2 = szFile + "_";
		g_oTraceFile.open(ilp2.c_str() );
		for(int i = 1; i <= nBlocks; ++ i)
		{
			g_oTraceFile << i << " ";
			if( i%10 == 0 )
				g_oTraceFile << endl;
		}
		g_oTraceFile.close();
	}	
	
	funcFile.close();
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
	CACHE_SET::DumpRefresh(outf);
	outf.close();
	
	// dump pair-wise graph
	outf.open(KnobGraphFile.Value().c_str());
	Graph::DumpGraph(outf);
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

void Graph::DumpGraph(ostream &os)
{
	os << "###1" << endl;
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
	map<UINT32, map<int, map<int, ADDRINT> > >::iterator i2i2i_p = g_sGraph.begin(), i2i2i_e = g_sGraph.end();
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