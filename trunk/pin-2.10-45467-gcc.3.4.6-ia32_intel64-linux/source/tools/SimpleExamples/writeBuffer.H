#ifndef WRITE_BUFFER_H
#define WRITE_BUFFER_H

#include <list>
#include <string>
#include <fstream>
#include "tool.H"

#define BUFFER_SIZE


class CVictimBuffer
{
public:
	CVictimBuffer(UINT32 nSize, UINT32 nLineSize, void *pNextLevel=NULL);
	//void SetLineSize( UINT32 nLineSize ) { m_nLineSize = nLineSize; }
	//void SetNextLevel( void *pNextLevel) { m_pNextLevel = pNextLevel; }
	int Access(ADDRINT nAddr, UINT32 nSize, ACCESS_BASE::ACCESS_TYPE );	
	int AccessSingleLine(ADDRINT nAddr, ACCESS_BASE::ACCESS_TYPE );
	//string StatsLong(string prefix);
	ostream &StatsDump(string prefix, ostream &os);
	
private:
	UINT32 m_nSize;
	UINT32 m_nLineSize;
	std::list<UINT> m_tags;
	

	void *m_pNextLevel;
	
	UINT64 m_nReadHit;
	UINT64 m_nReadMiss;
	UINT64 m_nWriteHit;
	UINT64 m_nWriteMiss;
	UINT64 m_nWriteBack;
	
private:	
	UINT32 Size() { return m_nSize; }
	UINT32 LineSize() { return m_nLineSize; }
	bool Hit(ADDRINT nTag);
	int Load(ADDRINT nAddr);
	int WriteBack();

};






#endif
