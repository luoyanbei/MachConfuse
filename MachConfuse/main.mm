#include "typedefine.h"
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <stdio.h>
#import "OCTools.h"
#include <string.h>
#import "Header.h"
#import "Disasm.h"
#import "AsmAnalyse.h"
#import "MachOpt.h"

#import "DyldInfo.h"

using namespace std;


static void const *imageAt(uint32_t location,void * buffer)
{
    auto p = (uint8_t const *)buffer;
    return p ? p + location : NULL;
}

struct SingleAss {
    uint32_t singleAss;
};


#define MATCH_STRUCT(obj,location,buffer) \
struct obj const * obj = (struct obj *)imageAt(location,buffer); \
if (!obj) [NSException raise:@"null exception" format:@#obj " is null"];


bool is_fat;


union macho_vnode_header {
    struct mach_header	mach_header;
    struct fat_header	fat_header;
    char	__pad[512];
} __header;

uint64_t FileGetSize(char *file_path){
    struct stat buf;
    if (stat(file_path,&buf) < 0 )
    {
        perror(file_path);
        exit(1);
    }
    return buf.st_size;
}

void confuseMethodName(const string &methodName, string &sOuterName, set<string> &searchSet)
{
    if (methodName.empty())
    {
        return;
    }
    
    string EncodeTable = "_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    int pos = rand()%(EncodeTable.size()-10);
    char first = EncodeTable[pos];
    string sConfuseName;
    sConfuseName.push_back(first);
    NSLog(@"%s\n", methodName.c_str());
    for (int i = 0; i < methodName.size()-1; i++)
    {
        if (methodName[i+1] == ':')
        {
            sConfuseName.push_back(':');
            continue;
        }
        pos = rand()%EncodeTable.size();
        char item = EncodeTable[pos];
        sConfuseName.push_back(item);
    }
    set<string>::iterator iter = searchSet.find(sConfuseName);
    if (iter == searchSet.end())
    {
        searchSet.insert(sConfuseName);
        sOuterName = sConfuseName;
    }
    else
    {
        confuseMethodName(methodName, sOuterName, searchSet);
    }
    
}

void findSectionAndConfuse(section *pSec, uint8_t *pBegin, const map<string, string> &canChangeNameMap, const string &sFindSecName)
{
    printf("section sectname = %s\n", pSec->sectname);
    printf("section segname = %s\n", pSec->segname);
    printf("section addr = %x\n", pSec->addr);
    printf("section size = %x\n", pSec->size);
    printf("section offset = %x\n", pSec->offset);
    printf("section align = %u\n", pSec->align);
    printf("section reloff = %u\n", pSec->reloff);
    printf("section  = %u\n", pSec->nreloc);
    printf("section  = %u\n", pSec->flags);
    printf("section  = %u\n", pSec->reserved1);
    printf("section  = %u\n", pSec->reserved2);
    uint8_t *methodAdd = pBegin + pSec->offset;
    long subSize = 0;
    long totalSize = pSec->size;
    set<string> methodSet;
    
    while ((totalSize -= subSize) > 0)
    {
        string methodName = (char*)methodAdd;
        subSize = methodName.size()+1;
        
        map<string, string>::const_iterator iter = canChangeNameMap.find(methodName);
        
        if (iter != canChangeNameMap.end())
        {
            methodName = (*iter).second;
            memcpy(methodAdd, methodName.c_str(), methodName.size());
            cout << methodAdd << endl;
        }
        methodAdd += subSize;
    }
}

void findSectionAndConfuse64(section_64 *pSec, uint8_t *pBegin, const map<string, string> &canChangeNameMap, const string &sFindSecName)
{
    printf("section sectname = %s\n", pSec->sectname);
    printf("section segname = %s\n", pSec->segname);
    printf("section addr = %llu\n", pSec->addr);
    printf("section size = %llu\n", pSec->size);
    printf("section offset = %u\n", pSec->offset);
    printf("section align = %u\n", pSec->align);
    printf("section reloff = %u\n", pSec->reloff);
    printf("section  = %u\n", pSec->nreloc);
    printf("section  = %u\n", pSec->flags);
    printf("section  = %u\n", pSec->reserved1);
    printf("section  = %u\n", pSec->reserved2);
    uint8_t *methodAdd = pBegin + pSec->offset;
    long subSize = 0;
    long totalSize = pSec->size;
    set<string> methodSet;
    
    
    while ((totalSize -= subSize) > 0)
    {
        string methodName = (char*)methodAdd;
        subSize = methodName.size()+1;
        
        map<string, string>::const_iterator iter = canChangeNameMap.find(methodName);
        
        if (iter != canChangeNameMap.end())
        {
            methodName = (*iter).second;
            memcpy(methodAdd, methodName.c_str(), methodName.size());
            cout << methodAdd << endl;
        }
        
        methodAdd += subSize;
        
    }
    
    
}



void confuseString(uint8_t *pBegin, symtab_command * pSymtab,char* buf, size_t bufsize){
    
    string EncodeTable = "_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    
    int pos=0;
    
    printf("after change...................\n");
    
    for(int i=0; i< bufsize;i++)
    {
        pos = rand()%EncodeTable.size();
        
        buf[i] = EncodeTable[pos];
        
        printf("%c",buf[i]);
    }
    
    printf("\n");
    memcpy(pBegin + pSymtab->stroff,buf, bufsize);
}













//-------------------------------------------------

static size_t getFileSize(FILE* file) {
    fseek(file, 0, SEEK_END);
    size_t read_len = ftell(file);
    fseek(file, 0, SEEK_SET);
    return read_len;
}

static size_t getFileSize(const char* filePath) {
    FILE* file = fopen(filePath, "rb");
    if (file == nullptr) {
        return 0;
    }
    size_t size = getFileSize(file);
    fclose(file);
    return size;
}

static void * convertSectionToBuff_64(segment_command_64 *segment)
{
    int Len = 0;
    size_t size = sizeof(segment_command_64);
    //Len = strlen(segment.name) + strlen(m.body);
    void * buf = malloc(size);
    if (NULL != buf)
    {
        //strcpy(buf, (char *)segment.cmd);
        //strcat(buf, (char *)segment.cmdsize)
    }
    
    return buf;
    //puts(buf);
    free(buf);
    buf = NULL;
}

static void * createNewMemory(void * buf1,size_t buf1_size, uint8_t *insertLocbegin,void *insert_objc,size_t insert_size)
{
    int Len = 0;
    size_t size = sizeof(segment_command_64);
    //Len = strlen(segment.name) + strlen(m.body);
    void * buf = malloc(size);
    if (NULL != buf)
    {
        //strcpy(buf, (char *)segment.cmd);
        //strcat(buf, (char *)segment.cmdsize)
    }
    
    return buf;
    //puts(buf);
    free(buf);
    buf = NULL;
}


void test1(void){
    
    char *src = "http://www.w3cschool.cc";
    char *src2 ="bbbb";
    char dest[50];
    
    printf("Before memcpy dest = %s\n", dest);
    memcpy(dest, src, strlen(src)+1);
    printf("After memcpy dest = %s\n", dest);
    memcpy(dest+strlen(src), src2, strlen(src2)+1);
    printf("2After memcpy dest = %s\n", dest);
    
}

//插入字符串
int test2(string sFilePath,string sFilePath_2)
{
    
    FILE *fp_open = fopen(sFilePath.c_str(), "r");
    uint64_t file_size = FileGetSize((char*)sFilePath.c_str());
    
    if (!fp_open)
    {
        printf("file isn't exist\n");
        return -1;
    }
    
    printf("file size is %llu\n\n", file_size);
    void *file_buf = malloc(file_size);
    
    if(fread(file_buf, 1, file_size, fp_open) != file_size)
    {
        printf("fread error\n");
        return -1;
    }
    
    fclose(fp_open);
    
    // 判断是否为胖文件
    union macho_vnode_header *header = (union macho_vnode_header*)file_buf;
    
    
    if (header->mach_header.magic == MH_MAGIC ||
        header->mach_header.magic == MH_MAGIC_64) {
        is_fat = FALSE;
    } else if (header->fat_header.magic == FAT_MAGIC ||
               header->fat_header.magic == FAT_CIGAM) {
        is_fat = TRUE;
    }
    else {
        printf("文件格式错误");
        return -1;
    }
    
    printf("Is fat: %d\n", is_fat);
    
    fat_header *fHeader = nullptr;
    
    int numA = 1;
    
    if(is_fat)
    {
        printf("多架构\n");
        fHeader = (fat_header *)file_buf;
        printf("header magic %x \n", fHeader->magic);
        printf("header nfat_arch %u \n", ntohl(fHeader->nfat_arch));
        numA = ntohl(fHeader->nfat_arch);
    }
    else
    {
        printf("单架构\n");
    }
    
    for (int i = 0; i < numA; i++)
    {
        
        mach_header *mhHeader = NULL;
        mach_header_64 *mhHeader64 = NULL;
        uint8_t *pLcAllBegin = NULL;
        fat_arch *parch = nullptr;
        uint8_t *pBegin = nullptr;
        uint32_t size;
        int ncmds = 0;
        int is32 = 1;
        
        if(is_fat)
        {
            printf("---------------------------\n");
            parch = (fat_arch *)((char*)file_buf+sizeof(fat_header)+i*sizeof(fat_arch));
            printf("header cputype %u \n", ntohl(parch->cputype));
            printf("header cpusubtype %u \n", ntohl(parch->cpusubtype));
            printf("header offset %u \n", ntohl(parch->offset));
            printf("header size %u \n", ntohl(parch->size));
            printf("header align %u \n", ntohl(parch->align));
            pBegin = (uint8_t*)file_buf + ntohl(parch->offset);
            size = ntohl(parch->size);
            
            if (ntohl(parch->cputype) == CPU_TYPE_ARM)
            {
                mhHeader = (mach_header *)pBegin;
                pLcAllBegin = pBegin + sizeof(mach_header);
                ncmds = mhHeader->ncmds;
                
                printf("+++++++++++++++++++++++++++\n");
                printf("mhHeader magic %x \n", mhHeader->magic);
                printf("mhHeader cputype %u \n", mhHeader->cputype);
                printf("mhHeader cpusubtype %u \n", mhHeader->cpusubtype);
                printf("mhHeader fileType %u \n", mhHeader->filetype);
                printf("mhHeader ncmds %u \n", mhHeader->ncmds);
                printf("mhHeader sizeofcmds %u \n", mhHeader->sizeofcmds);
                printf("mhHeader flags %u \n", mhHeader->flags);
                printf("+++++++++++++++++++++++++++\n");
                
            }
            
            if (ntohl(parch->cputype) == CPU_TYPE_ARM64)
            {
                mhHeader64 = (mach_header_64 *)pBegin;
                pLcAllBegin = pBegin + sizeof(mach_header_64);
                ncmds = mhHeader64->ncmds;
                
                printf("+++++++++++++++++++++++++++\n");
                printf("mhHeader magic %x \n", mhHeader64->magic);
                printf("mhHeader cputype %u \n", mhHeader64->cputype);
                printf("mhHeader cpusubtype %u \n", mhHeader64->cpusubtype);
                printf("mhHeader fileType %u \n", mhHeader64->filetype);
                printf("mhHeader ncmds %u \n", mhHeader64->ncmds);
                printf("mhHeader sizeofcmds %u \n", mhHeader64->sizeofcmds);
                printf("mhHeader flags %u \n", mhHeader64->flags);
                printf("+++++++++++++++++++++++++++\n");
                
            }
        }
        else
        {
            pBegin = (uint8_t*)file_buf;
            mhHeader = (mach_header*)pBegin;
            if(mhHeader->magic==MH_MAGIC||mhHeader->magic==MH_CIGAM)
            {
                is32 = 1;
            }
            else if(mhHeader->magic==MH_MAGIC_64||mhHeader->magic==MH_CIGAM_64)
            {
                is32 = 0;
            }
            
            ncmds = mhHeader->ncmds;
            
            pLcAllBegin = pBegin+(is32?sizeof(mach_header):sizeof( mach_header_64));
            
            printf("+++++++++++++++++++++++++++\n");
            printf("mhHeader magic %x \n", mhHeader->magic);
            printf("mhHeader cputype %u \n", mhHeader->cputype);
            printf("mhHeader cpusubtype %u \n", mhHeader->cpusubtype);
            printf("mhHeader fileType %u \n", mhHeader->filetype);
            printf("mhHeader ncmds %u \n", mhHeader->ncmds);
            printf("mhHeader sizeofcmds %u \n", mhHeader->sizeofcmds);
            printf("mhHeader flags %u \n", mhHeader->flags);
            printf("+++++++++++++++++++++++++++\n");
            
        }
        
        
        uint32_t sumLcoffSize = 0;
        printf("Load Commands Info:\n");
        //需要增加的字符串
        char * str_test = "aaaaaaaaaaaaa15";
        
        // size 增大,包含结束符
        int str_length = 16;//dddd
        
        
        for (int j = 0; j < ncmds; j++)
        {
            load_command *pLc = (load_command *)(pLcAllBegin + sumLcoffSize);
            printf("%s\n", [[OCTools getNameForCommand:pLc->cmd] UTF8String]);
            printf("load_command cmd = %u\n", pLc->cmd);
            
            printf("load_command size = %u\n", pLc->cmdsize);
            
            segment_command *pSc32;
            segment_command_64 *pSc64;
            symtab_command * pSymtab;
            
            sumLcoffSize += pLc->cmdsize;
            
            
            
            if (pLc->cmd == LC_SEGMENT_64)
            {
                pSc64 = (segment_command_64 *)pLc;
                
                int isAfter_cstring = 0;//是否已经过了“__cstring”
                
                
                if (strncmp(pSc64->segname, "__TEXT", strlen("__TEXT")) == 0)
                {
                    for (int x = 0; x < pSc64->nsects; x++)
                    {
                        section_64 *pSec = (section_64 *)((char*)pSc64 + sizeof(segment_command_64) + x*sizeof(section_64));
                        
                        printf("Section64 Header(%s)\n",pSec->sectname);
                        
                        if ((strncmp(pSec->sectname, "__cstring", strlen("__cstring")) == 0))
                        {
                            isAfter_cstring = 1;
                            
                            printf("**********************************\n");
                            
                            uint64_t    size = pSec->size;
                            
                            uint32_t offset = pSec->offset;
                            
                            
                            //修改cstring块的size
                            pSec->size = size+str_length;//测试
                            
                            //创建一个新的内存空间，保存
                            void * rBuff = malloc(file_size + str_length);
                            
                            printf("size=(%d);pSec->size=(%d)\n",(int)size,(int)pSec->size);
                            
                            //复制第 1 部分
                            uint32_t sumLcoffSize_1 = offset + size;//测试
                            
                            memcpy(rBuff,file_buf ,sumLcoffSize_1);
                            printf("第1部分(起点：0)(length：%d)\n",(int)sumLcoffSize_1);
                            
                            //增加字符串
                            uint32_t sumLcoffSize_3 = sumLcoffSize_1;
                            int strTest_length = (int)strlen(str_test)+1;
                            
                            memcpy(((char *)rBuff+sumLcoffSize_3),str_test ,strTest_length);
                            
                            printf("第2部分(起点：%d)(length：%d),str.length=(%d)\n",(int)sumLcoffSize_3,(int)strTest_length,strTest_length);
                            
                            //复制 字符串之后的内容
                            uint32_t sumLcoffSize_4 = sumLcoffSize_3 + strTest_length;
                            
                            memcpy(((char *)rBuff+sumLcoffSize_4),(char *)file_buf+sumLcoffSize_3 ,file_size-sumLcoffSize_3);
                            
                            printf("第3部分(起点：%d)(length：%d)\n",(int)sumLcoffSize_4,(int)file_size-sumLcoffSize_3);
                            
                            
                            printf("file_size=(%d)\n",(int)file_size);
                            
                            
                            FILE *fp = fopen(sFilePath_2.c_str(), "w");
                            
                            fwrite(rBuff, 1, file_size+str_length, fp);
                            fclose(fp);
                            
                            free(file_buf);
                            free(rBuff);
                            
                            printf("rBuff=写入完成\n");
                            
                            printf("**********************************\n");
                            
                        }
                    }
                    
                }
                
                
            }
            
            continue;
            
        }
        
        void *tmpOther = (void *)(pLcAllBegin + sumLcoffSize);
        
    }
    
    return 0;
}



int searchClassNameInCodeBlock(string sFilePath,string sFilePath_2)
{
    FILE *fp_open = fopen(sFilePath.c_str(), "r");
    uint64_t file_size = FileGetSize((char*)sFilePath.c_str());
    
    if (!fp_open)
    {
        printf("file isn't exist\n");
        return -1;
    }
    
    printf("file size is %llu\n\n", file_size);
    void *file_buf = malloc(file_size);
    
    if(fread(file_buf, 1, file_size, fp_open) != file_size)
    {
        printf("fread error\n");
        return -1;
    }
    
    fclose(fp_open);
    
    // 判断是否为胖文件
    union macho_vnode_header *header = (union macho_vnode_header*)file_buf;
    
    if (header->mach_header.magic == MH_MAGIC ||
        header->mach_header.magic == MH_MAGIC_64) {
        is_fat = FALSE;
    } else if (header->fat_header.magic == FAT_MAGIC ||
               header->fat_header.magic == FAT_CIGAM) {
        is_fat = TRUE;
    }
    else {
        printf("文件格式错误");
        return -1;
    }
    
    printf("Is fat: %d\n", is_fat);
    
    fat_header *fHeader = nullptr;
    
    int numA = 1;
    
    if(is_fat)
    {
        printf("多架构\n");
        fHeader = (fat_header *)file_buf;
        printf("header magic %x \n", fHeader->magic);
        printf("header nfat_arch %u \n", ntohl(fHeader->nfat_arch));
        numA = ntohl(fHeader->nfat_arch);
    }
    else
    {
        printf("单架构\n");
    }
    
    for (int i = 0; i < numA; i++)
    {
        mach_header *mhHeader = NULL;
        mach_header_64 *mhHeader64 = NULL;
        uint8_t *pLcAllBegin = NULL;
        fat_arch *parch = nullptr;
        uint8_t *pBegin = nullptr;
        uint32_t size;
        int ncmds = 0;
        int is32 = 1;
        
        if(is_fat)
        {
            printf("---------------------------\n");
            parch = (fat_arch *)((char*)file_buf+sizeof(fat_header)+i*sizeof(fat_arch));
            printf("header cputype %u \n", ntohl(parch->cputype));
            printf("header cpusubtype %u \n", ntohl(parch->cpusubtype));
            printf("header offset %u \n", ntohl(parch->offset));
            printf("header size %u \n", ntohl(parch->size));
            printf("header align %u \n", ntohl(parch->align));
            pBegin = (uint8_t*)file_buf + ntohl(parch->offset);
            size = ntohl(parch->size);
            
            if (ntohl(parch->cputype) == CPU_TYPE_ARM)
            {
                mhHeader = (mach_header *)pBegin;
                pLcAllBegin = pBegin + sizeof(mach_header);
                ncmds = mhHeader->ncmds;
                
                printf("+++++++++++++++++++++++++++\n");
                printf("mhHeader magic %x \n", mhHeader->magic);
                printf("mhHeader cputype %u \n", mhHeader->cputype);
                printf("mhHeader cpusubtype %u \n", mhHeader->cpusubtype);
                printf("mhHeader fileType %u \n", mhHeader->filetype);
                printf("mhHeader ncmds %u \n", mhHeader->ncmds);
                printf("mhHeader sizeofcmds %u \n", mhHeader->sizeofcmds);
                printf("mhHeader flags %u \n", mhHeader->flags);
                printf("+++++++++++++++++++++++++++\n");
                
            }
            
            if (ntohl(parch->cputype) == CPU_TYPE_ARM64)
            {
                mhHeader64 = (mach_header_64 *)pBegin;
                pLcAllBegin = pBegin + sizeof(mach_header_64);
                ncmds = mhHeader64->ncmds;
                
                printf("+++++++++++++++++++++++++++\n");
                printf("mhHeader magic %x \n", mhHeader64->magic);
                printf("mhHeader cputype %u \n", mhHeader64->cputype);
                printf("mhHeader cpusubtype %u \n", mhHeader64->cpusubtype);
                printf("mhHeader fileType %u \n", mhHeader64->filetype);
                printf("mhHeader ncmds %u \n", mhHeader64->ncmds);
                printf("mhHeader sizeofcmds %u \n", mhHeader64->sizeofcmds);
                printf("mhHeader flags %u \n", mhHeader64->flags);
                printf("+++++++++++++++++++++++++++\n");
                
            }
        }
        else
        {
            pBegin = (uint8_t*)file_buf;
            mhHeader = (mach_header*)pBegin;
            if(mhHeader->magic==MH_MAGIC||mhHeader->magic==MH_CIGAM)
            {
                is32 = 1;
            }
            else if(mhHeader->magic==MH_MAGIC_64||mhHeader->magic==MH_CIGAM_64)
            {
                is32 = 0;
            }
            
            ncmds = mhHeader->ncmds;
            
            pLcAllBegin = pBegin+(is32?sizeof(mach_header):sizeof( mach_header_64));
            
            printf("+++++++++++++++++++++++++++\n");
            printf("mhHeader magic %x \n", mhHeader->magic);
            printf("mhHeader cputype %u \n", mhHeader->cputype);
            printf("mhHeader cpusubtype %u \n", mhHeader->cpusubtype);
            printf("mhHeader fileType %u \n", mhHeader->filetype);
            printf("mhHeader ncmds %u \n", mhHeader->ncmds);
            printf("mhHeader sizeofcmds %u \n", mhHeader->sizeofcmds);
            printf("mhHeader flags %u \n", mhHeader->flags);
            printf("+++++++++++++++++++++++++++\n");
            
        }
        
        
        uint32_t sumLcoffSize = 0;
        printf("Load Commands Info:\n");
        
        
        
        for (int j = 0; j < ncmds; j++)
        {
            load_command *pLc = (load_command *)(pLcAllBegin + sumLcoffSize);
            printf("%s\n", [[OCTools getNameForCommand:pLc->cmd] UTF8String]);
            printf("load_command cmd = %u\n", pLc->cmd);
            
            printf("load_command size = %u\n", pLc->cmdsize);
            
            segment_command *pSc32;
            segment_command_64 *pSc64;
            symtab_command * pSymtab;
            
            sumLcoffSize += pLc->cmdsize;
            
            if (pLc->cmd == LC_SEGMENT_64)
            {
                pSc64 = (segment_command_64 *)pLc;
                
                int isAfter_cstring = 0;//是否已经过了“__cstring”
                
                if (strncmp(pSc64->segname, "__TEXT", strlen("__TEXT")) == 0 || strncmp(pSc64->segname, "__BD_TEXT", strlen("__BD_TEXT")) == 0)
                {
                    for (int x = 0; x < pSc64->nsects; x++)
                    {
                        section_64 *pSec = (section_64 *)((char*)pSc64 + sizeof(segment_command_64) + x*sizeof(section_64));
                        
                        printf("Section64 Header(%s)\n",pSec->sectname);
                        
                        if ((strncmp(pSec->sectname, "__text", strlen("__text")) == 0))
                        {
                            printf("**********************************\n");
                            
                            uint64_t size = pSec->size;
                            
                            uint32_t offset = pSec->offset;
                            uint64_t addr = pSec->addr;
                            
                            int count = size/4;
                            
                            printf("pBegin = %lx\n",pBegin);
                            printf("pSec->size=(%x); pSec->offset=(%lx); addr=(%lx); count= (%d)\n",(int)pSec->size,pSec->offset,addr,count);
                            
                            // __text的起始地址
                            uint64_t textAddr_base = (uint64_t)pBegin+offset;
                            printf("textAddr= %lx\n",textAddr_base);
                            // 011000D4
                            uint64_t target = 0x5847F6C0;//ldr x0, #0x8fed8;//0xD4001001;//svc 0x80
                            
                            //反汇编
                            Disasm * disasm = [[Disasm alloc] init];
                            //                            [disasm disASM:file_buf];
                            uint32_t my_offset = 0x20;
                            uint32_t my_size = 0x1E8;
                            // 0x100036C20
                            //                            [disasm disAsmWithBuff:file_buf offset:(pSec->offset+my_offset) size:my_size addr:(uint64_t)(pSec->addr + my_offset)];
                            
                            NSArray * asmArray = [disasm disAsmWithBuff:file_buf offset:(0x36C20) size:my_size addr:(uint64_t)(0x100036C20)];
                            //从arm汇编代码中 获取类名地址
                            NSArray * addrClassName = [[AsmAnalyse alloc] analyseAsmArray:asmArray];
                            
                            dumpSection_data_objc_classrefs((const struct mach_header *)mhHeader, "", "", 5);
                            
                            return 1;
                            
                            
                            
                            
                            
                            
                            for(int i=0; i<count; i++)
                            {
                                struct SingleAss * sAss = (struct SingleAss *)(textAddr_base+4*i);
                                //                                printf("sAss->singleAss = %x\n",sAss->singleAss);
                                uint64_t theAddr = (uint64_t)sAss-(uint64_t)pBegin;
                                
                                
                                
                                if(sAss->singleAss == target)
                                {
                                    printf("theAddr = %x\n",theAddr);
                                    
                                    
                                }
                                
                            }
                            
                            
                            
                            
                            FILE *fp = fopen(sFilePath_2.c_str(), "w");
                            
                            fwrite((void*)pBegin, 1, file_size, fp);
                            fclose(fp);
                            
                            free(file_buf);
                            
                            printf("rBuff=写入完成\n");
                            
                            printf("**********************************\n");
                            printf("wj--结束\n");
                            
                            
                            return 0;
                            
                        }
                        
                        
                    }
                    
                }
                
                
            }
            
            
            continue;
            
            
        }
        
        void *tmpOther = (void *)(pLcAllBegin + sumLcoffSize);
        
    }
    
    return 0;
}

int searchSVC(string sFilePath,string sFilePath_2)
{
    
    FILE *fp_open = fopen(sFilePath.c_str(), "r");
    uint64_t file_size = FileGetSize((char*)sFilePath.c_str());
    
    if (!fp_open)
    {
        printf("file isn't exist\n");
        return -1;
    }
    
    printf("file size is %llu\n\n", file_size);
    void *file_buf = malloc(file_size);
    
    if(fread(file_buf, 1, file_size, fp_open) != file_size)
    {
        printf("fread error\n");
        return -1;
    }
    
    fclose(fp_open);
    
    // 判断是否为胖文件
    union macho_vnode_header *header = (union macho_vnode_header*)file_buf;
    
    if (header->mach_header.magic == MH_MAGIC ||
        header->mach_header.magic == MH_MAGIC_64) {
        is_fat = FALSE;
    } else if (header->fat_header.magic == FAT_MAGIC ||
               header->fat_header.magic == FAT_CIGAM) {
        is_fat = TRUE;
    }
    else {
        printf("文件格式错误");
        return -1;
    }
    
    printf("Is fat: %d\n", is_fat);
    
    fat_header *fHeader = nullptr;
    
    int numA = 1;
    
    if(is_fat)
    {
        printf("多架构\n");
        fHeader = (fat_header *)file_buf;
        printf("header magic %x \n", fHeader->magic);
        printf("header nfat_arch %u \n", ntohl(fHeader->nfat_arch));
        numA = ntohl(fHeader->nfat_arch);
    }
    else
    {
        printf("单架构\n");
    }
    
    for (int i = 0; i < numA; i++)
    {
        
        mach_header *mhHeader = NULL;
        mach_header_64 *mhHeader64 = NULL;
        uint8_t *pLcAllBegin = NULL;
        fat_arch *parch = nullptr;
        uint8_t *pBegin = nullptr;
        uint32_t size;
        int ncmds = 0;
        int is32 = 1;
        
        if(is_fat)
        {
            printf("---------------------------\n");
            parch = (fat_arch *)((char*)file_buf+sizeof(fat_header)+i*sizeof(fat_arch));
            printf("header cputype %u \n", ntohl(parch->cputype));
            printf("header cpusubtype %u \n", ntohl(parch->cpusubtype));
            printf("header offset %u \n", ntohl(parch->offset));
            printf("header size %u \n", ntohl(parch->size));
            printf("header align %u \n", ntohl(parch->align));
            pBegin = (uint8_t*)file_buf + ntohl(parch->offset);
            size = ntohl(parch->size);
            
            if (ntohl(parch->cputype) == CPU_TYPE_ARM)
            {
                mhHeader = (mach_header *)pBegin;
                pLcAllBegin = pBegin + sizeof(mach_header);
                ncmds = mhHeader->ncmds;
                
                printf("+++++++++++++++++++++++++++\n");
                printf("mhHeader magic %x \n", mhHeader->magic);
                printf("mhHeader cputype %u \n", mhHeader->cputype);
                printf("mhHeader cpusubtype %u \n", mhHeader->cpusubtype);
                printf("mhHeader fileType %u \n", mhHeader->filetype);
                printf("mhHeader ncmds %u \n", mhHeader->ncmds);
                printf("mhHeader sizeofcmds %u \n", mhHeader->sizeofcmds);
                printf("mhHeader flags %u \n", mhHeader->flags);
                printf("+++++++++++++++++++++++++++\n");
                
            }
            
            if (ntohl(parch->cputype) == CPU_TYPE_ARM64)
            {
                mhHeader64 = (mach_header_64 *)pBegin;
                pLcAllBegin = pBegin + sizeof(mach_header_64);
                ncmds = mhHeader64->ncmds;
                
                printf("+++++++++++++++++++++++++++\n");
                printf("mhHeader magic %x \n", mhHeader64->magic);
                printf("mhHeader cputype %u \n", mhHeader64->cputype);
                printf("mhHeader cpusubtype %u \n", mhHeader64->cpusubtype);
                printf("mhHeader fileType %u \n", mhHeader64->filetype);
                printf("mhHeader ncmds %u \n", mhHeader64->ncmds);
                printf("mhHeader sizeofcmds %u \n", mhHeader64->sizeofcmds);
                printf("mhHeader flags %u \n", mhHeader64->flags);
                printf("+++++++++++++++++++++++++++\n");
                
            }
        }
        else
        {
            pBegin = (uint8_t*)file_buf;
            mhHeader = (mach_header*)pBegin;
            if(mhHeader->magic==MH_MAGIC||mhHeader->magic==MH_CIGAM)
            {
                is32 = 1;
            }
            else if(mhHeader->magic==MH_MAGIC_64||mhHeader->magic==MH_CIGAM_64)
            {
                is32 = 0;
            }
            
            ncmds = mhHeader->ncmds;
            
            pLcAllBegin = pBegin+(is32?sizeof(mach_header):sizeof( mach_header_64));
            
            printf("+++++++++++++++++++++++++++\n");
            printf("mhHeader magic %x \n", mhHeader->magic);
            printf("mhHeader cputype %u \n", mhHeader->cputype);
            printf("mhHeader cpusubtype %u \n", mhHeader->cpusubtype);
            printf("mhHeader fileType %u \n", mhHeader->filetype);
            printf("mhHeader ncmds %u \n", mhHeader->ncmds);
            printf("mhHeader sizeofcmds %u \n", mhHeader->sizeofcmds);
            printf("mhHeader flags %u \n", mhHeader->flags);
            printf("+++++++++++++++++++++++++++\n");
            
        }
        
        
        uint32_t sumLcoffSize = 0;
        printf("Load Commands Info:\n");
        //需要增加的字符串
        char * str_test = "aaaaaaaaaaaaa15";
        
        // size 增大,包含结束符
        int str_length = 16;//dddd
        
        
        for (int j = 0; j < ncmds; j++)
        {
            load_command *pLc = (load_command *)(pLcAllBegin + sumLcoffSize);
            printf("%s\n", [[OCTools getNameForCommand:pLc->cmd] UTF8String]);
            printf("load_command cmd = %u\n", pLc->cmd);
            
            printf("load_command size = %u\n", pLc->cmdsize);
            
            segment_command *pSc32;
            segment_command_64 *pSc64;
            symtab_command * pSymtab;
            
            sumLcoffSize += pLc->cmdsize;
            
            
            
            if (pLc->cmd == LC_SEGMENT_64)
            {
                pSc64 = (segment_command_64 *)pLc;
                
                int isAfter_cstring = 0;//是否已经过了“__cstring”
                
                //找到代码段
                if (strncmp(pSc64->segname, "__TEXT", strlen("__TEXT")) == 0 || strncmp(pSc64->segname, "__BD_TEXT", strlen("__BD_TEXT")) == 0)
                {
                    for (int x = 0; x < pSc64->nsects; x++)
                    {
                        section_64 *pSec = (section_64 *)((char*)pSc64 + sizeof(segment_command_64) + x*sizeof(section_64));
                        
                        printf("Section64 Header(%s)\n",pSec->sectname);
                        
                        if ((strncmp(pSec->sectname, "__text", strlen("__text")) == 0))
                        {
                            printf("**********************************\n");
                            
                            uint64_t size = pSec->size;
                            
                            uint32_t offset = pSec->offset;
                            uint32_t addr = pSec->addr;
                            
                            int count = size/4;
                            
                            printf("pBegin = %lx\n",pBegin);
                            printf("pSec->size=(%x); pSec->offset=(%lx); addr=(%lx); count= (%d)\n",(int)pSec->size,pSec->offset,addr,count);
                            
                            // __text的起始地址
                            uint64_t textAddr_base = (uint64_t)pBegin+offset;
                            printf("textAddr= %lx\n",textAddr_base);
                            // 011000D4
                            uint64_t target = 0xD4001001;//svc 0x80
                            uint64_t target_2 = 0xD4001021;//svc 0x81
                            uint64_t target_3 = 0xD4001041;//svc 0x82
                            
                            uint32_t target_test = 0x90ffaaa8;
                            
                            int ignoreCount = 161;
                            
                            for(int i=0; i<count; i++)
                            {
                                struct SingleAss * sAss = (struct SingleAss *)(textAddr_base+4*i);
                                //                                printf("sAss->singleAss = %x\n",sAss->singleAss);
                                uint64_t theAddr = (uint64_t)sAss-(uint64_t)pBegin;
                                
                                if(i<10 || i>count-10 || sAss->singleAss==0x7AF73C0)
                                {
                                    printf(" 0x%lx 位置: %lx \n",theAddr,sAss->singleAss);
                                }
                                
                                if(sAss->singleAss == target)// || sAss->singleAss==target_2 || sAss->singleAss==target_3)
                                {
                                    printf("theAddr = %x\n",theAddr);
//                                    修改svc命令 为 nop(1F2003D5)
                                    printf("清除 0x%lx 位置的 svc \n",theAddr);
                                    
                                    /*
                                     范围：
                                     (0x7AF43A4 - 0x3BC000)
                                     (0x7AF4898 - 0x3BC000)
                                     */
                                    
                                    if(theAddr>=(0x7AF43A4 - 0x3BC000) && theAddr<=(0x7AF4898 - 0x3BC000)){
                                        printf("跳过--清除 0x%lx 位置: %lx 改为 D503201F\n",theAddr,sAss->singleAss);
                                        sAss->singleAss = 0xD503201F;
                                        
                                    }
                                    else {
                                        
                                        printf("清除 0x%lx 位置: %lx 改为 D503201F\n",theAddr,sAss->singleAss);
                                    }
                                    
                                                                        
                                    if(theAddr == (0x870002C-0x3BC000)){
                                        printf("清除 0x%lx 位置: %lx 改为 D503201F; ida地址：0x%lx\n",theAddr,sAss->singleAss,theAddr+0x1003BC000);

                                        sAss->singleAss = 0xD503201F;
                                        ignoreCount--;
                                    }
                                    
                                    
                                }
                            }
                                                        
                            
                            FILE *fp = fopen(sFilePath_2.c_str(), "w");
                            
                            fwrite((void*)pBegin, 1, file_size, fp);
                            fclose(fp);
                            
                            free(file_buf);
                            
                            printf("rBuff=写入完成\n");
                            
                            printf("**********************************\n");
                            printf("wj--结束\n");
                            
                            
                            return 0;
                            
                        }
                        
                    }
                    
                }
                
            }
            continue;
            
        }
        
        void *tmpOther = (void *)(pLcAllBegin + sumLcoffSize);
        
    }
    
    return 0;
}

//写字符串到文件
void WriteToFile(char*str)
{
    string sFilePath = "/Users/wangjun1/Documents/test/加固保iOS加壳测试/machConfuseTest/log.txt";
    
    FILE * a = fopen(sFilePath.c_str(),"w");
    fwrite(str,1,strlen(str),a);
    fclose(a);
}


//--------------------------------------------------------------
//剪掉codeSignature部分
int testCutOffCodeSignature(string sFilePath)
{
    //0xdc90
    FILE *fp_open = fopen(sFilePath.c_str(), "r");
    uint64_t file_size = FileGetSize((char*)sFilePath.c_str());
    
    if (!fp_open)
    {
        printf("file isn't exist\n");
        return -1;
    }
    
    printf("file size is %llu\n\n", file_size);
    void *file_buf = malloc(file_size);
    
    if(fread(file_buf, 1, file_size, fp_open) != file_size)
    {
        printf("fread error\n");
        return -1;
    }
    
    fclose(fp_open);
    
    uint64_t codeSignatureSize = 10960;
    void *result_buf = malloc(file_size-codeSignatureSize);
    
    //复制二进制buf
    memcpy(result_buf,file_buf ,file_size-codeSignatureSize);
    
    FILE *fp = fopen("/Users/king/Desktop/2018ycyd/项目/混淆项目/增加垃圾代码/测试用二进制/testApp4_noCodeSignature", "w");
    
    fwrite(result_buf, 1, file_size-codeSignatureSize, fp);
    fclose(fp);
    
    free(file_buf);
    free(result_buf);
    
    printf("剪掉CodeSignature写入完成\n");
    
    return 0;
}

int test3_changeOffset(string sFilePath, string sFilePath_3)
{
    
    FILE *fp_open = fopen(sFilePath.c_str(), "r");
    uint64_t file_size = FileGetSize((char*)sFilePath.c_str());
    
    if (!fp_open)
    {
        printf("file isn't exist\n");
        return -1;
    }
    
    printf("file size is %llu\n\n", file_size);
    void *file_buf = malloc(file_size);
    
    if(fread(file_buf, 1, file_size, fp_open) != file_size)
    {
        printf("fread error\n");
        return -1;
    }
    
    fclose(fp_open);
    
    // 判断是否为胖文件
    union macho_vnode_header *header = (union macho_vnode_header*)file_buf;
    
    
    if (header->mach_header.magic == MH_MAGIC ||
        header->mach_header.magic == MH_MAGIC_64) {
        is_fat = FALSE;
    } else if (header->fat_header.magic == FAT_MAGIC ||
               header->fat_header.magic == FAT_CIGAM) {
        is_fat = TRUE;
    }
    else
    {
        printf("文件格式错误");
        return -1;
    }
    
    printf("Is fat: %d\n", is_fat);
    
    fat_header *fHeader = nullptr;
    
    int numA = 1;
    
    if(is_fat)
    {
        printf("多架构\n");
        fHeader = (fat_header *)file_buf;
        printf("header magic %x \n", fHeader->magic);
        printf("header nfat_arch %u \n", ntohl(fHeader->nfat_arch));
        numA = ntohl(fHeader->nfat_arch);
    }
    else
    {
        printf("单架构\n");
    }
    
    for (int i = 0; i < numA; i++)
    {
        mach_header *mhHeader = NULL;
        mach_header_64 *mhHeader64 = NULL;
        uint8_t *pLcAllBegin = NULL;
        fat_arch *parch = nullptr;
        uint8_t *pBegin = nullptr;
        uint32_t size;
        int ncmds = 0;
        int is32 = 1;
        
        if(is_fat)
        {
            printf("---------------------------\n");
            parch = (fat_arch *)((char*)file_buf+sizeof(fat_header)+i*sizeof(fat_arch));
            printf("header cputype %u \n", ntohl(parch->cputype));
            printf("header cpusubtype %u \n", ntohl(parch->cpusubtype));
            printf("header offset %u \n", ntohl(parch->offset));
            printf("header size %u \n", ntohl(parch->size));
            printf("header align %u \n", ntohl(parch->align));
            pBegin = (uint8_t*)file_buf + ntohl(parch->offset);
            size = ntohl(parch->size);
            
            if (ntohl(parch->cputype) == CPU_TYPE_ARM)
            {
                mhHeader = (mach_header *)pBegin;
                pLcAllBegin = pBegin + sizeof(mach_header);
                ncmds = mhHeader->ncmds;
                
                printf("+++++++++++++++++++++++++++\n");
                printf("mhHeader magic %x \n", mhHeader->magic);
                printf("mhHeader cputype %u \n", mhHeader->cputype);
                printf("mhHeader cpusubtype %u \n", mhHeader->cpusubtype);
                printf("mhHeader fileType %u \n", mhHeader->filetype);
                printf("mhHeader ncmds %u \n", mhHeader->ncmds);
                printf("mhHeader sizeofcmds %u \n", mhHeader->sizeofcmds);
                printf("mhHeader flags %u \n", mhHeader->flags);
                printf("+++++++++++++++++++++++++++\n");
                
            }
            
            if (ntohl(parch->cputype) == CPU_TYPE_ARM64)
            {
                mhHeader64 = (mach_header_64 *)pBegin;
                pLcAllBegin = pBegin + sizeof(mach_header_64);
                ncmds = mhHeader64->ncmds;
                
                printf("+++++++++++++++++++++++++++\n");
                printf("mhHeader magic %x \n", mhHeader64->magic);
                printf("mhHeader cputype %u \n", mhHeader64->cputype);
                printf("mhHeader cpusubtype %u \n", mhHeader64->cpusubtype);
                printf("mhHeader fileType %u \n", mhHeader64->filetype);
                printf("mhHeader ncmds %u \n", mhHeader64->ncmds);
                printf("mhHeader sizeofcmds %u \n", mhHeader64->sizeofcmds);
                printf("mhHeader flags %u \n", mhHeader64->flags);
                printf("+++++++++++++++++++++++++++\n");
                
            }
        }
        else
        {
            pBegin = (uint8_t*)file_buf;
            mhHeader = (mach_header*)pBegin;
            if(mhHeader->magic==MH_MAGIC||mhHeader->magic==MH_CIGAM)
            {
                is32 = 1;
            }
            else if(mhHeader->magic==MH_MAGIC_64||mhHeader->magic==MH_CIGAM_64)
            {
                is32 = 0;
            }
            
            ncmds = mhHeader->ncmds;
            
            pLcAllBegin = pBegin+(is32?sizeof(mach_header):sizeof( mach_header_64));
            
            printf("+++++++++++++++++++++++++++\n");
            printf("mhHeader magic %x \n", mhHeader->magic);
            printf("mhHeader cputype %u \n", mhHeader->cputype);
            printf("mhHeader cpusubtype %u \n", mhHeader->cpusubtype);
            printf("mhHeader fileType %u \n", mhHeader->filetype);
            printf("mhHeader ncmds %u \n", mhHeader->ncmds);
            printf("mhHeader sizeofcmds %u \n", mhHeader->sizeofcmds);
            printf("mhHeader flags %u \n", mhHeader->flags);
            printf("+++++++++++++++++++++++++++\n");
            
        }
        
        
        uint32_t sumLcoffSize = 0;
        printf("Load Commands Info:\n");
        
        int isAfter_cstring = 0;//是否已经过了“__cstring”
        int str_length = 16;//需要修改的长度
        
        for (int j = 0; j < ncmds; j++)
        {
            load_command *pLc = (load_command *)(pLcAllBegin + sumLcoffSize);
            printf("%s\n", [[OCTools getNameForCommand:pLc->cmd] UTF8String]);
            printf("load_command cmd = %u\n", pLc->cmd);
            
            
            printf("load_command size = %u\n", pLc->cmdsize);
            segment_command *pSc32 = nullptr;
            segment_command_64 *pSc64;
            symtab_command * pSymtab;
            
            sumLcoffSize += pLc ->cmdsize;
            
            
            
            if (pLc->cmd == LC_SEGMENT_64)
            {
                pSc64 = (segment_command_64 *)pLc;
                
                
                if (strncmp(pSc64->segname, "__TEXT", strlen("__TEXT")) == 0)
                {
                    //当前段的 offset不变，修改 filesize vmsize
                    pSc64->filesize = pSc64->filesize + str_length;
                    pSc64->vmsize = pSc64->vmsize + str_length;
                    
                    
                    
                    for (int x = 0; x < pSc64->nsects; x++)
                    {
                        section_64 *pSec = (section_64 *)((char*)pSc64 + sizeof(segment_command_64) + x*sizeof(section_64));
                        
                        printf("Section64 Header(%s);offset(%d);length(%d)\n",pSec->sectname,(int)pSec->offset,(int)pSec->size);
                        
                        if ((strncmp(pSec->sectname, "__cstring", strlen("__cstring")) == 0))
                        {
                            isAfter_cstring = 1;
                            continue;
                        }
                        else
                        {
                            if(isAfter_cstring==1)
                            {
                                printf("Section64 Header(%s)\n",pSec->sectname);
                                // 偏移增加
                                pSec->offset = pSec->offset + str_length;
                                pSec->addr = pSec->addr + str_length;
                            }
                        }
                    }
                    //break;
                }
                
                //数据段
                if (strncmp(pSc64->segname, "__DATA", strlen("__DATA")) == 0)
                {
                    
                    
                    
                    if(isAfter_cstring == 1)
                    {
                        //当前段的 offset  vmsize
                        pSc64->fileoff = pSc64->fileoff + str_length;
                        pSc64->vmaddr = pSc64->vmaddr + str_length;
                    }
                    
                    for (int x = 0; x < pSc64->nsects; x++)
                    {
                        section_64 *pSec = (section_64 *)((char*)pSc64 + sizeof(segment_command_64) + x*sizeof(section_64));
                        
                        printf("Section64 Header(%s)\n",pSec->sectname);
                        // section偏移增加
                        pSec->offset = pSec->offset + str_length;
                        pSec->addr = pSec->addr + str_length;
                        
                    }
                }
                
                if (strncmp(pSc64->segname, "__LINKEDIT", strlen("__LINKEDIT")) == 0)
                {
                    // segment偏移增加
                    pSc64->vmaddr = pSc64->vmaddr + str_length;
                    pSc64->fileoff = pSc64->fileoff + str_length;
                    //pSc64->filesize = pSc64->filesize + str_length;//本次暂不修改此项
                }
                
            }
            else if(pLc->cmd == LC_DYLD_INFO_ONLY)
            {
                if(isAfter_cstring == 1)
                {
                    //结构体是 struct dyld_info_command {
                    dyld_info_command * dInfo_com = (dyld_info_command *)pLc;
                    
                    dInfo_com->rebase_off = dInfo_com->rebase_off + str_length;
                    dInfo_com->bind_off = dInfo_com->bind_off + str_length;
                    dInfo_com->lazy_bind_off = dInfo_com->lazy_bind_off + str_length;
                    dInfo_com->export_off = dInfo_com->export_off + str_length;
                }
                
            }
            else if(pLc->cmd == LC_SYMTAB)
            {
                if(isAfter_cstring == 1)
                {
                    //结构体是 struct symtab_command {
                    symtab_command * dInfo_com = (symtab_command *)pLc;
                    
                    dInfo_com->symoff = dInfo_com->symoff + str_length;
                    dInfo_com->stroff = dInfo_com->stroff + str_length;
                }
            }
            else if(pLc->cmd == LC_DYSYMTAB)
            {
                if(isAfter_cstring == 1)
                {
                    //结构体是 struct dysymtab_command
                    dysymtab_command * theCmd = (dysymtab_command *)pLc;
                    theCmd->indirectsymoff = theCmd->indirectsymoff + str_length;
                }
            }
            else if(pLc->cmd == LC_MAIN)
            {
                //程序的入口位置，本次并没有影响到现在的入口位置，因此不变
                if(isAfter_cstring == 1)
                {
                    //结构体是 struct
                    //entry_point_command * theCmd = (entry_point_command *)pLc;
                    //theCmd->entryoff = theCmd->entryoff + str_length;
                }
            }
            else if(pLc->cmd == LC_FUNCTION_STARTS)
            {
                
                if(isAfter_cstring == 1)
                {
                    //结构体是
                    linkedit_data_command * theCmd = (linkedit_data_command *)pLc;
                    theCmd->dataoff = theCmd->dataoff + str_length;
                }
            }
            
            else if(pLc->cmd == LC_DATA_IN_CODE)
            {
                if(isAfter_cstring == 1)
                {
                    //结构体是
                    linkedit_data_command * theCmd = (linkedit_data_command *)pLc;
                    theCmd->dataoff = theCmd->dataoff + str_length;
                }
            }
            
            if(pLc->cmd == LC_CODE_SIGNATURE)
            {
                //签名相关
                //结构体是
                linkedit_data_command * theCmd = (linkedit_data_command *)pLc;
                
                if(isAfter_cstring == 1)
                {
                    printf("CodeSignature--1-dataoff=(%d)\n",theCmd->dataoff);
                    
                    theCmd->dataoff = theCmd->dataoff + str_length;
                    
                    printf("CodeSignature--2-dataoff=(%d)\n",theCmd->dataoff);
                    
                }
                
                //解析codeSignature结构
                printf("CodeSignature---cmdsize=(%d)\n",theCmd->cmdsize);
                printf("CodeSignature---datasize=(%d)\n",theCmd->datasize);
                
                //Code Signature的头部信息
                CS_SuperBlob * theHead = (CS_SuperBlob*)((char *)file_buf+theCmd->dataoff);
                
                printf("magic=(%x)\n",ntohl(theHead->magic));
                printf("length=(%d)\n",ntohl(theHead->length));
                
                int count = (int)ntohl(theHead->count);
                printf("count=(%d)\n",ntohl(theHead->count));
                
                
                CS_BlobIndex *blobIndex = (CS_BlobIndex *)theHead->index;
                
                for(int i=0; i<count; i++)
                {
                    CS_BlobIndex tmp_blobIndex = (CS_BlobIndex)theHead->index[i];
                    
                    printf("CS_BlobIndex--type=(%d)\n",ntohl(tmp_blobIndex.type));
                    printf("CS_BlobIndex--offset=(0x%x)\n",ntohl(tmp_blobIndex.offset));
                    
                    if(ntohl(tmp_blobIndex.type)==0)
                    {
                        CS_CodeDirectory * codeDic = (CS_CodeDirectory *)((char *)theHead+ntohl(tmp_blobIndex.offset));
                        
                        printf("CS_CodeDirectory---magic=(%x)\n",ntohl(codeDic->magic));
                        printf("CS_CodeDirectory---length=(%d)\n",ntohl(codeDic->length));
                        printf("CS_CodeDirectory---version=(%d)\n",ntohl(codeDic->version));
                        printf("CS_CodeDirectory---flags=(%d)\n",ntohl(codeDic->flags));
                        printf("CS_CodeDirectory---hashOffset=(%x)\n",ntohl(codeDic->hashOffset));
                        printf("CS_CodeDirectory---identOffset=(%x)\n",ntohl(codeDic->identOffset));
                        printf("CS_CodeDirectory---nSpecialSlots=(%d)\n",ntohl(codeDic->nSpecialSlots));
                        printf("CS_CodeDirectory---nCodeSlots=(%d)\n",ntohl(codeDic->nCodeSlots));
                        printf("CS_CodeDirectory---codeLimit=(%d)\n",ntohl(codeDic->codeLimit));
                        printf("CS_CodeDirectory---hashSize=(%d)\n",ntohl(codeDic->hashSize));
                        printf("CS_CodeDirectory---hashType=(%d)\n",ntohl(codeDic->hashType));
                        printf("CS_CodeDirectory---platform=(%d)\n",ntohl(codeDic->platform));
                        printf("CS_CodeDirectory---pageSize=(%d)\n",ntohl(codeDic->pageSize));
                        printf("CS_CodeDirectory---spare2=(%d)\n",ntohl(codeDic->spare2));
                        printf("CS_CodeDirectory---scatterOffset=(%x)\n",ntohl(codeDic->scatterOffset));
                        printf("CS_CodeDirectory---teamOffset=(%x)\n",ntohl(codeDic->teamOffset));
                        
                        printf("------------------------------------\n\n");
                        
                        char * hashInfo = (char *)((char *)codeDic+ntohl(codeDic->hashOffset));
                        printf("CS_CodeDirectory---hashInfo=(%s)\n",hashInfo);
                        //写入一个文件中
                        WriteToFile(hashInfo);
                        
                        char * identInfo = (char*)((char *)codeDic+ntohl(codeDic->identOffset));
                        printf("CS_CodeDirectory---identInfo=(%s)\n",identInfo);
                        
                        char * scatterInfo = (char*)((char *)codeDic+ntohl(codeDic->scatterOffset));
                        printf("CS_CodeDirectory---scatterInfo=(%s)\n",scatterInfo);
                        
                        char * teamInfo = (char*)((char *)codeDic+ntohl(codeDic->teamOffset));
                        printf("CS_CodeDirectory---teamInfo=(%s)\n",teamInfo);
                        
                        printf("---------------\n\n");
                    }
                    
                    if(ntohl(tmp_blobIndex.type)==2)
                    {
                        CS_SuperBlob * supBlob = (CS_SuperBlob *)((char *)theHead+ntohl(tmp_blobIndex.offset));
                        
                        printf("2--magic=(%x)\n",ntohl(supBlob->magic));
                        printf("2--length=(%d)\n",ntohl(supBlob->length));
                        int count = (int)ntohl(supBlob->count);
                        printf("2--count=(%d)\n",count);
                        
                        
                        for(int i=0; i<count; i++)
                        {
                            CS_BlobIndex tmp_blobIndex = (CS_BlobIndex)supBlob->index[i];
                            
                            printf("2--CS_BlobIndex--type=(%d)\n",ntohl(tmp_blobIndex.type));
                            printf("2--CS_BlobIndex--offset=(0x%x)\n",ntohl(tmp_blobIndex.offset));
                            
                            CS_GenericBlob * genericBlob = (CS_GenericBlob *)((char *)supBlob+ntohl(tmp_blobIndex.offset));
                            
                            printf("2--CS_GenericBlob--magic=(%x)\n",ntohl(genericBlob->magic));
                            printf("2--CS_GenericBlob--length=(%d)\n",ntohl(genericBlob->length));
                            printf("2--CS_GenericBlob--data=(%s)\n",(char *)(genericBlob->data));
                            printf("\n\n");
                        }
                        printf("---------------\n\n");
                        
                    }
                    
                    if(ntohl(tmp_blobIndex.type)==5)
                    {
                        
                        CS_GenericBlob * generBlob = (CS_GenericBlob *)((char *)theHead+ntohl(tmp_blobIndex.offset));
                        
                        printf("3--magic=(%x)\n",ntohl(generBlob->magic));
                        printf("3--length=(%d)\n",ntohl(generBlob->length));
                        printf("3--data=(%s)\n",generBlob->data);
                        printf("---------------\n\n");
                        
                    }
                    //第四个条目
                    if(ntohl(tmp_blobIndex.type)==4096)
                    {
                        CS_CodeDirectory * codeDic = (CS_CodeDirectory *)((char *)theHead+ntohl(tmp_blobIndex.offset));
                        
                        printf("4---magic=(%x)\n",ntohl(codeDic->magic));
                        printf("4---length=(%d)\n",ntohl(codeDic->length));
                        printf("4---version=(%d)\n",ntohl(codeDic->version));
                        printf("4---flags=(%d)\n",ntohl(codeDic->flags));
                        printf("4---hashOffset=(%x)\n",ntohl(codeDic->hashOffset));
                        printf("4---identOffset=(%x)\n",ntohl(codeDic->identOffset));
                        printf("4---nSpecialSlots=(%d)\n",ntohl(codeDic->nSpecialSlots));
                        printf("4---nCodeSlots=(%d)\n",ntohl(codeDic->nCodeSlots));
                        printf("4---codeLimit=(%d)\n",ntohl(codeDic->codeLimit));
                        printf("4---hashSize=(%d)\n",ntohl(codeDic->hashSize));
                        printf("4---hashType=(%d)\n",ntohl(codeDic->hashType));
                        printf("4---platform=(%d)\n",ntohl(codeDic->platform));
                        printf("4---pageSize=(%d)\n",ntohl(codeDic->pageSize));
                        printf("4---spare2=(%d)\n",ntohl(codeDic->spare2));
                        printf("4---scatterOffset=(%x)\n",ntohl(codeDic->scatterOffset));
                        printf("4---teamOffset=(%x)\n",ntohl(codeDic->teamOffset));
                        
                        printf("------------------------------------\n\n");
                        
                        char * hashInfo = (char *)((char *)codeDic+ntohl(codeDic->hashOffset));
                        printf("4---hashInfo=(%s)\n",hashInfo);
                        //写入一个文件中
                        WriteToFile(hashInfo);
                        
                        char * identInfo = (char*)((char *)codeDic+ntohl(codeDic->identOffset));
                        printf("4---identInfo=(%s)\n",identInfo);
                        
                        char * scatterInfo = (char*)((char *)codeDic+ntohl(codeDic->scatterOffset));
                        printf("4---scatterInfo=(%s)\n",scatterInfo);
                        
                        char * teamInfo = (char*)((char *)codeDic+ntohl(codeDic->teamOffset));
                        printf("4---teamInfo=(%s)\n",teamInfo);
                        
                        printf("---------------\n\n");
                    }
                    
                    if(ntohl(tmp_blobIndex.type)==65536)
                    {
                        CS_GenericBlob * generBlob = (CS_GenericBlob *)((char *)theHead+ntohl(tmp_blobIndex.offset));
                        
                        printf("5--magic=(%x)\n",ntohl(generBlob->magic));
                        printf("5--length=(%d)\n",ntohl(generBlob->length));
                        printf("5--data=(%s)\n",generBlob->data);
                        printf("---------------\n\n");
                        
                    }
                    
                }
                
            }
            
            
            
            continue;
            
        }
        
        FILE *fp = fopen(sFilePath_3.c_str(), "w");
        
        fwrite(file_buf, 1, file_size, fp);
        fclose(fp);
        
        free(file_buf);
        
        printf("rBuff=写入完成\n");
    }
    
    return 0;
}




//-------------------------------------------------
void test_searchClassnameFromAsm(string sFilePath){
    
    FILE *fp_open = fopen(sFilePath.c_str(), "r");
    uint64_t file_size = FileGetSize((char*)sFilePath.c_str());
    
    if (!fp_open)
    {
        printf("file isn't exist\n");
        return ;
    }
    
    printf("file size is %llu\n\n", file_size);
    void *file_buf = malloc(file_size);
    
    if(fread(file_buf, 1, file_size, fp_open) != file_size)
    {
        printf("fread error\n");
        return ;
    }
    
    fclose(fp_open);
    
    // 判断是否为胖文件
    
    mach_header * mhHeader = (mach_header*)file_buf;
    
    std::vector<struct segment_command_64 const *> segVector = findAllSegment(mhHeader);
    // 获取 Binding Info中 address 与 symbolename 的对应关系
    DyldInfo * dyldInfo = [[DyldInfo alloc] initWithFilePath:[NSString stringWithUTF8String:sFilePath.c_str()]];
    NSDictionary * symbolDict = [dyldInfo createBindingClassrefs_location:0x000cdbc0 length:0x000cdbc0 baseAddress:0x0000000100000000 nodeType:NodeTypeBind segments:segVector];
    NSLog(@"symbolDict=\n%@",symbolDict);
    
    const char * name_class = "SEASCallerBlockViewController";
    const char * name_method = "dealloc";
    
    uint64_t method_imp_addr = find_implementation_by_className_methName(mhHeader, name_class, name_method);
    NSLog(@"-[%s %s] 实现地址：%llx",name_class, name_method,method_imp_addr);
    //计算该函数内汇编长度，以ret结尾
        
    //反汇编
    Disasm * disasm = [[Disasm alloc] init];
    //                            [disasm disASM:file_buf];
    uint32_t my_offset = (uint32_t)method_imp_addr;
    uint64_t my_addr = (uint64_t)method_imp_addr;
    uint32_t my_size = 0x10;//400条，//0x1F40;//2000条arm汇编
    // 0x100036C20
    //                            [disasm disAsmWithBuff:file_buf offset:(pSec->offset+my_offset) size:my_size addr:(uint64_t)(pSec->addr + my_offset)];
    int endIndex = -1;//函数汇编结束标记"ret"在汇编数组中的下标
    AsmAnalyse * asmAnalyse = [[AsmAnalyse alloc] init];

    NSMutableArray * asmArray = [[NSMutableArray alloc] init];
    
    while(endIndex==-1){
        NSArray * asmArrayTmp = [disasm disAsmWithBuff:file_buf offset:my_offset size:my_size addr:(uint64_t)my_addr];
        
        //从arm汇编代码中 获取类名地址
        endIndex = [asmAnalyse findAsmArrayEndIndex:asmArrayTmp];
        if(endIndex==-1){
            NSLog(@"未找到结束标记");
            my_size = my_size+my_size;//更新数量
        }
        else{
            
            for(int i=0; i<=endIndex; i++){
                [asmArray addObject:asmArrayTmp[i]];
            }
        }
    }
        
    NSArray * addrClassName = [asmAnalyse analyseAsmArray:asmArray];
    NSLog(@"addr_ClassName地址：\n%@",addrClassName);
    
    //查找地址对应的类名
    for(NSString * addr in addrClassName){
        NSString * cName = [symbolDict objectForKey:addr];
        if(cName){
            NSLog(@"地址1(%@) %@",addr, cName);
        }
        else{
            char * name = find_class_from_objc_classrefs(mhHeader,[addr UTF8String]);
            NSLog(@"地址2(%@) %s",addr, name);
        }
    }
}


void * alter_svc_to_nop(void * file_buf, uint64_t target_addr)
{
    uint8_t *pBegin = (uint8_t*)file_buf;
    
   
    uint64_t target = 0xD4001001;//svc 0x80
    
    uint64_t textAddr_base = (uint64_t)pBegin+target_addr;

    struct SingleAss * sAss = (struct SingleAss *)(textAddr_base);

        
    if(sAss->singleAss == target)
    {
        sAss->singleAss = 0xD503201F;// nop
    }
    
    return file_buf;

}


//存储二进制到文件
void save_buf_to_file(void * file_buf, uint64_t file_size, string filePath_save){
        FILE *fp = fopen(filePath_save.c_str(), "w");
        uint8_t *pBegin = (uint8_t*)file_buf;
    
        fwrite((void*)pBegin, 1, file_size, fp);

        fclose(fp);

        free(file_buf);

        printf("rBuff=写入完成\n");

        printf("**********************************\n");
}



void * gain_fileBuf(string filePath_source)
{
    FILE * fp_open = fopen(filePath_source.c_str(), "r");
    uint64_t file_size = FileGetSize((char*)filePath_source.c_str());

    if (!fp_open)
    {
        printf("file isn't exist\n");
        return NULL;
    }
    
    printf("file size is %llu\n\n", file_size);
    void *file_buf = malloc(file_size);
    
    if(fread(file_buf, 1, file_size, fp_open) != file_size)
    {
        printf("fread error\n");
        return NULL;
    }
    
    fclose(fp_open);
    
    return file_buf;
}

//获取二进制文件中的代码段
vector<struct section_64 const *> gain_text_sections(void * file_buf)
{
    // 判断是否为胖文件
    mach_header * mhHeader = (mach_header*)file_buf;
    vector<struct section_64 const *> sectionArray;
    // 查找代码段
    struct section_64 const * sectionTxt_DB = findSection64ByName(mhHeader, "__text", "__BD_TEXT");//
    
    if(sectionTxt_DB==NULL){
        NSLog(@"找不到代码段--1");
    }
    else{
        sectionArray.push_back(sectionTxt_DB);
    }
    
    struct section_64 const * sectionTxt = findSection64ByName(mhHeader, "__text", "__TEXT");//
    
    if(sectionTxt==NULL){
        NSLog(@"找不到代码段--2");
    }
    else{
        sectionArray.push_back(sectionTxt);
    }
    
    return sectionArray;
}

vector<uint64_t> search_svc_from_asm(void * file_buf, vector<string> asmStrArray)
{
    vector<uint64_t> resultVec;//声明一个int型向量
    vector<struct section_64 const *> sectionArray = gain_text_sections(file_buf);
    
    if(sectionArray.size()<1){
        NSLog(@"找不到代码段--3");
        return resultVec;
    }
    
    for(int i=0; i<sectionArray.size(); i++){
        struct section_64 const * sectionTxt = sectionArray[i];
        
        // 展示 Section64_Header中的 offset 和 size
        uint64_t offset = sectionTxt->offset;
        uint64_t text_size = sectionTxt->size;
        
        int tmp_length = 4;//单条汇编所占内存
        
        //反汇编
        Disasm * disasm = [[Disasm alloc] init];

        uint32_t my_offset = (uint32_t)0;
        uint64_t my_addr = (uint64_t)offset;
        uint32_t my_size = 0x640;//400条
                    
        int asmStrCount = (int)asmStrArray.size();
        
        while(1){
            
            my_size = 0x640;
            
            if(my_offset==0){
                my_offset = (uint32_t)offset;
            }
            else{
                my_offset = my_offset + my_size - (asmStrCount-1)*tmp_length;
            }
            
            if(my_offset < text_size+offset && my_offset+my_size > text_size+offset)
            {
                my_size = (uint32_t)(text_size+offset-my_offset);
            }
            else if(my_offset>text_size+offset){
                break;
            }
            
            NSArray * asmArrayTmp = [disasm disAsmWithBuff:file_buf offset:my_offset size:my_size addr:(uint64_t)my_addr];
            
            int count = (int)[asmArrayTmp count];
            
            uint64_t first_addr = (uint32_t)my_offset;

            int samecount = 0;
            
            for(int i = 0; i<count; i++){
                NSString * curAsm = [asmArrayTmp objectAtIndex:i];
                
                for(int j=0; j<asmStrCount; j++){
                    if(j==samecount){
                        NSString * strTmp = [NSString stringWithCString:(asmStrArray[j]).c_str()  encoding:NSUTF8StringEncoding];

                        if([strTmp isEqualToString:curAsm])
                        {
                            samecount = samecount+1;
                            break;
                        }
                        else
                        {
                            samecount = 0;
                            break;
                        }
                    }
                }
                
                if(samecount==asmStrCount){
                    
                    uint64_t target_addr = (uint64_t)(first_addr+i*4);
                    NSLog(@"查找到svc调用反动态调试：0x%lx    %@", target_addr, curAsm);

                    resultVec.push_back(target_addr);

                    break;
                }
                
            }
            
        }
    }
    
    return resultVec;
    
}




int main(int argc, const char * argv[])
{
    //原文件路径
    string sFilePath = "/path/to/TestSpace";
    //存储路径
    string sFilePath_save = "/path/to/TestSpace_2";
    
    
    //将要搜索的汇编指令
    vector<string> svc_asm_vec = {"movz x0,#0x1f", "movz x1,#0", "movz x2,#0", "movz x3,#0", "movz w16,#0x1a", "svc #0x80"};

    vector<string> svc_asm_vec_2 = {"svc #0x80"};
    
    uint64_t file_size = FileGetSize((char*)sFilePath.c_str());//计算文件大小
    void *file_buf = gain_fileBuf(sFilePath.c_str());//加载文件到内存
    //搜索到的"svc #0x80"的地址
    vector<uint64_t> addr_arry = search_svc_from_asm(file_buf, svc_asm_vec);
    
    if(addr_arry.size()>0){
        void * file_buf_save = alter_svc_to_nop(file_buf, addr_arry[0]);//修改第一个svc为nop
        save_buf_to_file(file_buf_save, file_size, sFilePath_save);//存储修改后的二进制到本地文件
    }
    
    return 0;
}


