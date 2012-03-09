
#include "pin.H"

#include <iostream>
#include <fstream>
#include <map>

#include "tool.H"
#include "floatInst.H"

using namespace InstType;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,    "pintool",
    "o", "floatPoint.out", "specify dcache file name");
	
/* ===================================================================== */
/* Global variables */
/* ===================================================================== */


map<INT32, string> g_hNum2Inst;
map<string, INT32> g_hInst2Num;

// statistic
map<INT32, UINT64> g_hInterval;
map<INT32, UINT64> g_hInstCounter;
map<ADDRINT, UINT64> g_hAddr2Num;
int g_nCounter = 0;
UINT64 g_nTotalInsts = 0;

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr <<
        "This tool represents a float-point instruction collector.\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary() << endl; 
    return -1;
}

/* ===================================================================== */

void Load()
{
	for( int i = 0; i < FINST_NUM; ++ i)
	{
		g_hNum2Inst[g_FloatInstArr[i].m_nID] = g_FloatInstArr[i].m_szName;
		g_hInst2Num[g_FloatInstArr[i].m_szName] = g_FloatInstArr[i].m_nID;
		g_hInstCounter[g_FloatInstArr[i].m_nID] = 0;
	}
	
	for( int i = 0; i < AVXINST_NUM; ++ i)
	{
		g_hNum2Inst[g_AvxInstArr[i].m_nID] = g_AvxInstArr[i].m_szName;
		g_hInst2Num[g_AvxInstArr[i].m_szName] = g_AvxInstArr[i].m_nID;
		g_hInstCounter[g_AvxInstArr[i].m_nID] = 0;
	}
}

void OnFloatInstruction(UINT32 nID, ADDRINT nAddr)
{
	++ g_nCounter;
	++ g_hInterval[g_nCounter];
	++ g_hInstCounter[nID];
	++ g_hAddr2Num[nAddr];
	g_nCounter = 0;
}

void OnInstruction()
{
	++ g_nTotalInsts;
	++ g_nCounter;
}

VOID Instruction(INS ins, void * v)
{	
	const ADDRINT iaddr = INS_Address(ins);
	INS_InsertPredicatedCall(
		ins, IPOINT_BEFORE, (AFUNPTR) OnInstruction,
		IARG_END ); 
			
	string szOpc = INS_Mnemonic(ins);
	map<string, INT32>::iterator s2i_p = g_hInst2Num.find(szOpc);
	
	if(s2i_p != g_hInst2Num.end() )
	{	
		cerr << s2i_p->first << ":\t" << s2i_p->second << endl;
		UINT32 nID = s2i_p->second;
		
		INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE, (AFUNPTR) OnFloatInstruction,
			IARG_UINT32, nID,
			IARG_ADDRINT, iaddr,
			IARG_END );  
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
        "# Float Point Instruction stats\n"
        "#\n";
    out << "Total Instruction:\t" << g_nTotalInsts << ":\t" << ((double)g_nTotalInsts)/g_nTotalInsts;
	out << endl << "=====================================================" << endl;
	out << endl << "Float Instruction Interval:\t" << endl;
	
	map<INT32, UINT64>::iterator i2n_p = g_hInterval.begin(), i2n_e = g_hInterval.end();
	for(; i2n_p != i2n_e; ++ i2n_p)
	{
		out << i2n_p->first << ":\t" << i2n_p->second << endl;
	}	
	
	out << "\n====================================================" << endl;
	out << "Float Instruction Frequency:\t\n";
	i2n_p = g_hInstCounter.begin(), i2n_e = g_hInstCounter.end();
	for(; i2n_p != i2n_e; ++ i2n_p)
	{
		string szName = g_hNum2Inst[i2n_p->first];
		if( i2n_p->second != 0 )
			out << szName << ":\t" << i2n_p->second << endl;
	}      
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

    Load();
    
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns

    PIN_StartProgram();
    
    return 0;
}
