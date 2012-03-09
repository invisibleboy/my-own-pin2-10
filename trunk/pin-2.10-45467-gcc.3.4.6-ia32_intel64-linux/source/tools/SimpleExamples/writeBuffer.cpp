#include "writeBuffer.H"
#include "cacheL1.H"

CVictimBuffer::CVictimBuffer(UINT32 nSize, UINT32 nLineSize, void *pNextLevel)
{
	m_nSize = nSize;
	m_nLineSize = nLineSize;
	m_pNextLevel = pNextLevel;
	
	m_nReadHit = m_nReadMiss = m_nWriteHit = m_nWriteMiss = 0;
}

int CVictimBuffer::Access(ADDRINT nAddr, UINT32 nSize, ACCESS_BASE::ACCESS_TYPE accessType)
{
    const ADDRINT highnAddr = nAddr + nSize;

    const ADDRINT lineSize = LineSize();
    const ADDRINT notLineMask = ~(lineSize - 1);
    do
    {
       AccessSingleLine(nAddr, accessType);
       nAddr = (nAddr & notLineMask) + lineSize; // start of next cache line
    }
    while (nAddr < highnAddr);

    return 0;
}

int CVictimBuffer::AccessSingleLine(ADDRINT nAddr, ACCESS_BASE::ACCESS_TYPE accessType)
{
	ADDRINT nTag = ACCESS_BASE::Addr2Tag(nAddr, LineSize());
	bool bHit = Hit(nTag);
	
	if( bHit )
	{		
		if( accessType == ACCESS_BASE::ACCESS_TYPE_LOAD)
			++ m_nReadHit;
		else
			++ m_nWriteHit;			
	}
	else
	{		
		// 1. access the next level
		// 2. load into buffer, and store into buffer
		((CACHE_BASE *)m_pNextLevel)->AccessSingleLine(nAddr, ACCESS_BASE::ACCESS_TYPE_LOAD);  
		if( accessType == ACCESS_BASE::ACCESS_TYPE_STORE )  
		{
			++ m_nWriteMiss;
			Load(nAddr);					
		}			
		else 
			++ m_nReadMiss;
			
	}
	return 0;
}

int CVictimBuffer::Load(ADDRINT nAddr )
{
	ADDRINT nTag = ACCESS_BASE::Addr2Tag(nAddr, LineSize());
	if( m_tags.size() < m_nSize )
		m_tags.push_front( nTag);
	else if (m_tags.size() == m_nSize )
	{
		WriteBack();
		m_tags.push_front( nTag );
	}
	else
		assert(false);
	
	return 0;
}

bool CVictimBuffer::Hit(ADDRINT nTag)
{
	bool bHit = false;
	list<UINT>::iterator i_p = m_tags.begin(), i_e = m_tags.end();
	for(; i_p != i_e; ++ i_p)
	{
		UINT nTag1 = *i_p;
		if( nTag1 == nTag)
		{
			bHit = true;
			break;
		}
	}
	
	if( bHit && m_tags.front() != nTag)
	{
		m_tags.erase( i_p );
		m_tags.push_front(nTag);
	}
	
	return bHit;
}

int CVictimBuffer::WriteBack()
{
	ADDRINT nAddr = m_tags.back() * m_nLineSize;
	((CACHE_BASE *)m_pNextLevel)->AccessSingleLine(nAddr, ACCESS_BASE::ACCESS_TYPE_STORE);
	m_tags.pop_back();
	++ m_nWriteBack;
	return 0;
}

ostream & CVictimBuffer::StatsDump(string prefix, ostream &os)
{
	const UINT32 headerWidth = 19;
    const UINT32 numberWidth = 12;

	UINT64 nTotalAccess = m_nReadHit + m_nReadMiss + m_nWriteHit + m_nWriteMiss;
	
    string out;
    out += prefix + "victim buffer:" + "\n";
	out += prefix + "Entries: " + mydecstr(m_nSize, numberWidth) + "\n";
	
	out += prefix + ljstr("BufferR-Hits:      ", headerWidth)
           + mydecstr(m_nReadHit, numberWidth) +
           ":  " +fltstr(100.0 * m_nReadHit / nTotalAccess, 2, 6) + "%\n";

    out += prefix + ljstr("BufferW-Hits:    ", headerWidth)
           + mydecstr(m_nWriteHit, numberWidth) +
           ":  " +fltstr(100.0 * m_nWriteHit / nTotalAccess, 2, 6) + "%\n";

	out += "\n";
    out += prefix + ljstr("BufferR-Misses:  ", headerWidth)
           + mydecstr(m_nReadMiss, numberWidth) +
           ":  " +fltstr(100.0 * m_nReadMiss / nTotalAccess, 2, 6) + "%\n";
    
	
    out += prefix + ljstr("BufferW-Misses:  ", headerWidth)
           + mydecstr(m_nWriteMiss, numberWidth) +
           ":  " +fltstr(100.0 * m_nWriteMiss / nTotalAccess, 2, 6) + "%\n";
    out += "\n";
	

    out += prefix + ljstr("Buffer-Writeback:      ", headerWidth)
           + mydecstr(m_nWriteBack, numberWidth) +
           ":  " +fltstr(100.0 * m_nWriteBack / nTotalAccess, 2, 6) + "%\n";
	os << out;
	os << "=======================================\n";
	return os;
}

