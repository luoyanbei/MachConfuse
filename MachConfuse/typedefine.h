#ifndef _TYPEDEFINE_H_
#define _TYPEDEFINE_H_

// Ansi C++
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <list>
#include <queue>
#include <set>
#include <map>
#include <stack>
#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <ctime>
#include <utility>
#include <cmath>
using namespace std;

// ios

#import <AddressBook/AddressBook.h>
#include <sqlite3.h>
#include <objc/runtime.h>
#import <mach-o/loader.h>
#import <mach-o/dyld.h>
#import <mach-o/arch.h>
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>

// free bsd
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <netdb.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <net/if.h> 
#include <net/if_dl.h>
#include <sys/un.h>

#include <sys/ioctl.h>

// ios private
#include <dlfcn.h>
#include <zlib.h>



#define G_HARDWARE_FILE "/var/root/globalHardware/hardware"


typedef vector<char> ByteArray;

//extern ofstream g_LOG;

template<typename T1, typename T2>
inline T1 lexical_cast(const T2 &t)
{
    stringstream ss;
    
    ss << t;
    T1 tReturn;
    
    ss >> tReturn;
    
    return tReturn;
}

class TraceLog
{
public:
	TraceLog(const string &s, ostream &os = cout)
    : m_s(s), m_os(os)
	{
		m_ltime = time(NULL);
        threadid = pthread_self();
        
        char buff[32] = "";
        sprintf(buff, "%p", threadid);
        
		os << "--------" << s << "----" << buff << "---->" << endl;
        
        string sLog = "--------" + s + "----" + buff + "---->\n";
        NSLog(@"%s", sLog.c_str());
	}
    
	~TraceLog()
	{
        char buff[32] = "";
        sprintf(buff, "%p", threadid);
        
		time_t m_ltime1 = time(NULL);
		m_os << "<--------" << m_s << "----" << m_ltime1 - m_ltime << "----" << buff << "----" << endl;
        
        string sLog = "<--------" + m_s + "----" + lexical_cast<string>(m_ltime1 - m_ltime) + "----" + buff + "----\n";
        NSLog(@"%s", sLog.c_str());
	}
	
private:
	string m_s;
	ostream &m_os;
	time_t m_ltime;
    pthread_t threadid;
};

inline void trim(string &s)
{
    if (s.empty())
    {
        return;
    }
    
    string::size_type pos = s.find_first_not_of(" ");
    if (pos != 0)
    {
        s.erase(0, pos);
    }
    
    pos = s.find_last_not_of(" ");
    if (pos+1 != s.size())
    {
        s.erase(pos + 1);
    }
}

inline bool sleepx(const long int second, const long int usecond = 0L)
{
    timeval tv;
    tv.tv_sec = second;
    tv.tv_usec = usecond;
    
    int retval = select(0, NULL, NULL, NULL, &tv);
    
    if(retval == 0)
    {
        // 到时
        return true;
    }
    else
    {
        // 错误
        return false;
    }
}


// 读取文件的函数
inline bool ReadFile(string &s, const string &sPath)
{
	// 判断文件是否可读
    struct stat st;
    if(lstat(sPath.c_str(), &st) < 0)
    {
    	// pathname是文件名的绝对路径
        printf("lstate error %d\n", errno);
        return false;
    }
    
    if(S_ISDIR(st.st_mode) != 0)
    {
    	// 是文件夹
    	cout << "is dir!" << endl;
        return false;
    }
    
    const int size = st.st_size;
	
    ifstream in(sPath.c_str(), ios::binary);
	
    if(!in)
    {
    	string sErr = "con't open file " + sPath;
    	cout << sErr << endl;
        return false;
    }
	
    s.resize(size);
    in.read(&s[0], size);
    
    return true;
}

inline void StringToLower(string &s)
{
    for(int i = 0; i < s.size(); ++i)
    {
        if(isupper(s[i]) != 0)
        {
            s[i] = tolower(s[i]);
        }	
    }
}

inline bool isStringDigit(const string &s)
{
    if(s.size() == 0)
    {
        return false;
    }
    
    for(int i = 0; i < s.size(); ++i)
    {
        if(isdigit(s[i]) == 0)
        {
            return false;
        }
    }
    
    return true;
}


inline int findSz(const char *sz1, const char *sz2, int size1, int size2)
{
    if(sz1 == NULL || sz2 == NULL)
    {
        return -1;
    }
    
    if(size1 < size2)
    {
        return -1;
    }
    
    for(int i = 0; i < size1 - size2 + 1; ++i)
    {
        for(int j = 0; j < size2; ++j)
        {
            if(sz1[i + j] != sz2[j])
            {
                break;
            }
            
            if(j == size2 - 1)
            {
                return i;	
            }
        }
    }
    
    return -1;
}

// 字符串截取
// 输出参数，输入参数，头，尾
inline string::size_type Substr(string &sSub, const string &s, const string &sHead, const string &sTail, const string::size_type pos = 0)
{
    if(pos >= s.size())
    {
        return string::npos;
    }
    
    string::size_type pos1 = 0;
    string::size_type pos2 = 0;
    
    if((pos1 = s.find(sHead, pos)) == string::npos)
    {
        return string::npos;
    }
    
    if((pos2 = s.find(sTail, pos1 + sHead.size())) == string::npos)
    {
        string sErr = "cant find word: " + sTail;
        return string::npos;
    }
    
    sSub = s.substr(pos1 + sHead.size(), pos2 - pos1 - sHead.size());
    
    return pos2 + sTail.size();
}

inline bool isIpType(const char *szIp)
{
    const int size = strlen(szIp);
    for(int i = 0; i < size; ++i)
    {
        // not digit and not .
        if(isdigit(szIp[i]) == 0 && szIp[i] != '.')
        {
            return false;
        }
    }
    
    return true;
}

// 读取文件的函数
inline bool ReadFile(vector<char> &cvec, const string &sPath)
{
	// 判断文件是否可读
    struct stat st;
    if(lstat(sPath.c_str(), &st) < 0)
    {
    	// pathname是文件名的绝对路径
        printf("lstate error %d\n", errno);
        return false;
    }
    
    if(S_ISDIR(st.st_mode) != 0)
    {
    	// 是文件夹
    	cout << "is dir!" << endl;
        return false;
    }
    
    const int size = st.st_size;
	
    ifstream in(sPath.c_str(), ios::binary);
	
    if(!in)
    {
    	string sErr = "con't open file " + sPath;
    	cout << sErr << endl;
        return false;
    }
	
    cvec.resize(size);
    in.read(&cvec[0], size);
    
    return true;
}

inline bool writeFile(const string &s, const string &sFileName)
{
    NSLog(@"sFileName = %s     s = %s\n", sFileName.c_str(), s.c_str());
	ofstream out(sFileName.c_str(), ios::binary);

	if(!out)
	{
		return false;
	}
    
    out.write(s.c_str(), s.size());
	return true;
}

inline bool writeFile(const char *sz, const int size, const string &sFileName)
{
	ofstream out(sFileName.c_str(), ios::binary);
    
	if(!out)
	{
		return false;
	}
    
    out.write(sz, size);
	return true;
}

inline string &HexToChar(string &s, const vector<unsigned char> &data)
{
    s.clear();
	for(unsigned int i = 0; i < data.size(); ++i)
	{
	    char szBuff[3] = "";
	    sprintf(szBuff, "%02x", *reinterpret_cast<const unsigned char *>(&data[i]) & 0xff);
	    s.push_back(szBuff[0]);
	    s.push_back(szBuff[1]);
	}
	return s;
}

inline string &HexToChar(string &s, const char *data, int len)
{
    s.clear();
    for(unsigned int i = 0; i < len; ++i)
    {
        char szBuff[3] = "";
        sprintf(szBuff, "%02x", data[i] & 0xff);
        s.push_back(szBuff[0]);
        s.push_back(szBuff[1]);
    }
    return s;
}


inline void CharToHex(vector<unsigned char> &data, const string &s)
{
	data.clear();
	
	unsigned int ui = 0L;
	for(unsigned int i = 0; i < s.size(); ++i)
	{
		unsigned int localui = 0L;
		const char c = s[i];
		if('0' <= c && c <= '9')
		{
			localui = c - '0';
		}
		else if('A' <= c && c <= 'F')
		{
			localui = c - 'A' + 10;
		}
		else if('a' <= c && c <= 'f')
		{
			localui = c - 'a' + 10;
		}
		
	    if(i % 2 == 0)
	    {
	    	ui = localui * 16L;
	    }
	    else
	    {
	    	ui += localui;
	    	data.push_back(ui);
	    }
	}
}

inline long select_send(int sockfd, const char *buff, int size, int timeout)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);
    
    timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0L;
    
    int retval = select(sockfd + 1, NULL, &fds, NULL, &tv);
    
    if(retval < 0)
    {
        cout << "select error" << endl;
   	    return -2;
    }
    else if(retval == 0)
    {
        cout << "time out" << endl;
        return -3;
    }
    
    return send(sockfd, buff, size, 0);
}

inline long select_recv(int sockfd, char *buff, int maxlength, int timeout)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);
    
    timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0L;
    
    int retval = select(sockfd + 1, &fds, NULL, NULL, &tv);
    
    if(retval < 0)
    {
        cout << "select error" << endl;
        return -2;
    }
    else if(retval == 0)
    {
        cout << "time out" << endl;
        return -3;
    }
    
    memset(buff, 0, maxlength);
    return recv(sockfd, buff, maxlength, 0);
}

inline void showHex(const char *p, int size)
{
    for(int i = 0; i < size; ++i)
    {
        printf("%02x", p[i] & 0xff);
    }
    
    printf("\n");
}

inline void LOG(const string &s)
{
    NSLog(@"%s\n", s.c_str());
}

/*inline bool myConnect(int &sockfd)
{
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        cout << "socket error: " << strerror(errno) << endl;
        return false;
    }
    
    sockaddr_in me;
    memset(&me, 0, sizeof(sockaddr_in));
    me.sin_family = AF_INET;
    me.sin_port = htons(9830);
    me.sin_addr.s_addr = INADDR_ANY;
    
    int iMode = 1;
    if(ioctl(sockfd, FIONBIO, &iMode))
    {
        printf("ioctl to no block error!\n");
        return false;
    }
    
    printf("ioctl to no block success!\n");
    
    connect(sockfd, reinterpret_cast<sockaddr*>(&me), sizeof(sockaddr));
    
    timeval tm;
    tm.tv_sec  = 20;
    tm.tv_usec = 0;
    
    fd_set set;
    FD_ZERO(&set);
    FD_SET(sockfd, &set);
    if(select(sockfd + 1, NULL, &set, NULL, &tm) <= 0)
    {
        printf("connect time out, error!\n");
        return false;
    }
    
    int error = -1;
    socklen_t len = sizeof(socklen_t);
    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
    if(error != 0)
    {
        printf("socket opt error!\n");
        return false;
    }
    
    iMode = 0;
    int iResult = ioctl(sockfd, FIONBIO, &iMode);
    if(iResult)
    {
        printf("ioctl to block error!\n");
        return false;
    }
    
    printf("ioctl to block success!\n");
    return true;
}
*/

#endif
