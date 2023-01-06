//
//  MachOpt.m
//  MachConfuse
//
//  Created by wangjun1 on 2021/8/16.
//  Copyright © 2021 ldzspace. All rights reserved.
//

#import "MachOpt.h"
#import <sys/sysctl.h>
#import <mach-o/dyld.h>
//#include <substrate.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>

struct wj_objcConst_record
{
    uint64_t methodPoint;
};

struct wj_classrefs_record
{
    uint64_t data;
};

struct wj_data_64_point
{
    uint64_t point;
};

struct wj_method64_info
{
    uint64_t namePoint;
    uint64_t typesPoint;
    uint64_t impPoint;
};

struct wj_method64List_head
{
    uint32_t entrySize;
    uint32_t count;
};


struct wj_single_asm {
    uint32_t singleAsm;
};

using namespace std;

@implementation MachOpt



std::vector<struct segment_command_64 const *> findAllSegment(const struct mach_header *mh)
{
    std::vector<struct segment_command_64 const *> segVector;
    struct load_command *lc;
    
    char rpath[4096]; /* should be big enough for PATH_MAX */
    int i;
    char *tmp;
    //wj
    struct segment_command_64 *segCmd64 = NULL;
    
    /* extract basename */
    tmp = strrchr(rpath, '/');
    
    /* detect if this is a arm64 binary */
    if (mh->magic == MH_MAGIC_64) {
        lc = (struct load_command *)((unsigned char *)mh + sizeof(struct mach_header_64));
        printf("[+] detected 64bit ARM binary in memory.\n");
    } else { /* we might want to check for other errors here, too */
        lc = (struct load_command *)((unsigned char *)mh + sizeof(struct mach_header));
        printf("[+] detected 32bit ARM binary in memory.\n");
    }
    
    for (i=0; i<mh->ncmds; i++) {
        /*printf("Load Command (%d): %08x\n", i, lc->cmd);*/
        
        if (lc->cmd == LC_SEGMENT_64 || lc->cmd == LC_SEGMENT) {
            
            segCmd64 = (struct segment_command_64 *)lc;
            NSLog(@"wj--segname: %s",segCmd64->segname);
            
            segVector.push_back(segCmd64);
            
        }
        //切换到下一个 load comand
        lc = (struct load_command *)((unsigned char *)lc+lc->cmdsize);

    }
    
    return segVector;
}

struct section_64 const * findSection64ByName(const struct mach_header *mh,char const *sectnamechar ,char const *segnamet)
{
    struct load_command *lc;
    
    char rpath[4096]; /* should be big enough for PATH_MAX */
    int i;
    char *tmp;
    //wj
    struct segment_command_64 *segCmd64 = NULL;
    
    /* extract basename */
    tmp = strrchr(rpath, '/');
    NSLog(@"hook--wj--dump--app");
    
    /* detect if this is a arm64 binary */
    if (mh->magic == MH_MAGIC_64) {
        lc = (struct load_command *)((unsigned char *)mh + sizeof(struct mach_header_64));
        printf("[+] detected 64bit ARM binary in memory.\n");
    } else { /* we might want to check for other errors here, too */
        lc = (struct load_command *)((unsigned char *)mh + sizeof(struct mach_header));
        printf("[+] detected 32bit ARM binary in memory.\n");
    }
    
    for (i=0; i<mh->ncmds; i++) {
        /*printf("Load Command (%d): %08x\n", i, lc->cmd);*/
        
        if (lc->cmd == LC_SEGMENT_64) {
            
            segCmd64 = (struct segment_command_64 *)lc;
            NSLog(@"wj--segname: %s",segCmd64->segname);
            
            if (strncmp(segCmd64->segname, "__PAGEZERO", 16) != 0 && strncmp(segCmd64->segname, "__LINKEDIT", 16) != 0)
            {
                if (strncmp(segCmd64->segname, segnamet, 16) == 0)
                {
                    NSLog(@"wj--segname2: %s",segCmd64->segname);
                    
                    for(int w=0; w<segCmd64->nsects; w++)
                    {
                        struct section_64 const * section_64 = (struct section_64 *)((unsigned char *)lc+0x48+w*0x50);
                        NSLog(@"wj--section_64_sectname: %s",section_64->sectname);
                        
                        if (strncmp(section_64->sectname, sectnamechar, 16) == 0)
                        {
                            NSLog(@"wj--section_64_sectname: %s",section_64->sectname);
                            uint64_t offset = section_64->offset;
                            uint64_t size = section_64->size;
                            
                            NSLog(@"wj--section_64--offset: %lx",offset);
                            NSLog(@"wj--section_64--size: %lx",size);
                            
                            return section_64;
                            
                        }
                    }
                }
            }
            
            lc = (struct load_command *)((unsigned char *)lc+lc->cmdsize);
            
            continue;
        }
    }
    
    return NULL;
}


void dumpSection_data_objc_classrefs(const struct mach_header *mh, char rpath[4096], char npath[4096], int outfd)
{
    struct section_64 const * section_64 = findSection64ByName(mh, "__objc_classrefs", "__DATA");
    // 展示 Section64_Header中的 offset 和 size
    uint64_t offset = section_64->offset;
    uint64_t size = section_64->size;
    NSLog(@"section--sectName=(%s); segName=(%s); offset=(%lx); size=(%d)",section_64->sectname,section_64->segname,offset,size);
    
    int r,toread=8;
    int tmp_length = 8;//单条数据所占内存
    const int count = (int)size/tmp_length;
    
    uint64_t first_addr = ((uint64_t)mh + offset);
    NSLog(@"wj--section_64--first_addr : %llx",first_addr);

    for(int i=0; i<count; i++)
    {
        //自定义结构体
        struct wj_objcConst_record * record = (struct wj_objcConst_record*)(first_addr + i*tmp_length);
        
        uint64_t original_offset = ((uint64_t)record-(uint64_t)mh);
        NSLog(@"wj--section_64--original_offset : %llx",original_offset);
        
        NSLog(@"wj--section_64--method_name : %llx",record->methodPoint);
        
//        uint64_t mthname_str_addr = searchMethodnameAddress(mh, record->methodPoint);
//        NSLog(@"wj--section_64--(%s)地址(0x%lx)",record->methodPoint,mthname_str_addr);
//
//        if(mthname_str_addr==0)
//        {
//            NSLog(@"wj--section_64--(%s)地址为 0",record->methodPoint);
//        }
//        else
//        {
//            lseek(outfd, original_offset, SEEK_SET);
//            r = write(outfd, (unsigned char *)&mthname_str_addr, toread);
//            if (r != toread) {
//                printf("[-] Error writing file\n");
//                _exit(1);
//            }
//        }
        
    }

}



uint64_t getUInt64fromHex(char const *str)
{
    uint64_t accumulator = 0;
    for (size_t i = 0 ; isxdigit((unsigned char)str[i]) ; ++i)
    {
        char c = str[i];
        accumulator *= 16;
        if (isdigit(c)) /* '0' .. '9'*/
            accumulator += c - '0';
        else if (isupper(c)) /* 'A' .. 'F'*/
            accumulator += c - 'A' + 10;
        else /* 'a' .. 'f'*/
            accumulator += c - 'a' + 10;

    }
    return accumulator;
}

//根据 __objc_classrefs 节中的一个地址，查找到该地址对应的类名
// strAddr 是 加载的类在 classrefs 中的地址
char * find_class_from_objc_classrefs(const struct mach_header *mh, char const *strAddr)
{
    uint64_t addr = getUInt64fromHex(strAddr);
    //这是arm64架构的 头，不支持fat架构和32位架构
    uint64_t addr_refs = (uint64_t)mh+(uint32_t)addr;
    struct wj_classrefs_record * r_classrefs = (struct wj_classrefs_record *)addr_refs;
    uint32_t addr_objc_data = (uint32_t)r_classrefs->data;
    NSLog(@"wj--r_classrefs.data : %llx",addr_objc_data);
    //引用的其他库中的类，此时addr_objc_data为 0
    if(addr_objc_data<=0){
        return NULL;
    }
    // 获取（__DATA,__objc_const）中Class64 Info 中的 Data
    uint64_t data_addr = addr_objc_data+0x20+(uint64_t)mh;
    struct wj_data_64_point * data_class64_data = (struct wj_data_64_point *)(data_addr);
    // 获取（__DATA,__objc_data）中Class64中的 Name
    uint64_t name_addr = (uint32_t)data_class64_data->point +0x18 +(uint64_t)mh;
    struct wj_data_64_point * name_class64Info_data = (struct wj_data_64_point *)(name_addr);
    //classname字符串所在地址
    uint64_t addr_classname = (uint32_t)name_class64Info_data->point+(uint64_t)mh;
    char * cName = (char*)addr_classname;
    NSLog(@"className = (%s)",cName);
    return cName;
}

//从methodList中查找方法名对应的address
uint64_t find_impPoint_with_methodListHead(const struct mach_header *mh,struct wj_method64List_head* methodListHead, const char* methodName){
    int count = (int)methodListHead->count;
    uint32_t size = methodListHead->entrySize;
    uint64_t first_method_addr = (uint64_t)methodListHead+0x8;
    for(int i=0; i<count; i++){
        struct wj_method64_info * method_info = (struct wj_method64_info *)(first_method_addr+i*size);
        const char * name_method = (const char*)((uint32_t)method_info->namePoint + (uint64_t)mh);
        if(strcmp(name_method, methodName)==0){
            //类名相等，返回地址
            return method_info->impPoint;
        }
    }
    return 0;
}


uint64_t find_implementation_by_className_methName(const struct mach_header *mh,const char* className, const char * methName)
{
    struct section_64 const * section_64 = findSection64ByName(mh, "__objc_classlist", "__DATA");
    
    // 展示 Section64_Header中的 offset 和 size
    uint64_t offset = section_64->offset;
    uint64_t size = section_64->size;
    NSLog(@"section--sectName=(%s); segName=(%s); offset=(%lx); size=(%d)",section_64->sectname,section_64->segname,offset,size);
    
    int r,toread=8;
    int single_length = 8;//单条数据所占内存
    const int count = (int)size/single_length;
    
    uint64_t first_addr = ((uint64_t)mh + offset);
    NSLog(@"wj--section_64--first_addr : %llx",first_addr);

    for(int i=0; i<count; i++)
    {
        //自定义结构体
        struct wj_data_64_point * record = (struct wj_data_64_point*)(first_addr + i*single_length);
        // __objc_data中的地址
        uint64_t addr_objcData = (uint32_t)record->point + (uint64_t)mh;
        // __objc_data中的地址,找到 Data的地址
        uint64_t addr_objcData_data = addr_objcData+0x20;
        struct wj_data_64_point * r_objcData_data = (struct wj_data_64_point*)(addr_objcData_data);
        // __objc_const中的地址
        uint64_t addr_objcConst = (uint32_t)r_objcData_data->point + (uint64_t)mh;
        uint64_t addr_objcConst_name = addr_objcConst+0x18;
        uint64_t addr_objcConst_name_str = (uint32_t)((struct wj_data_64_point *)addr_objcConst_name)->point + (uint64_t)mh;

        const char * name_class = (const char *)addr_objcConst_name_str;
        //比较类名
        if(strcmp(name_class, className)==0){
            //类的方法地址
            uint64_t addr_objcConst_baseMethods = addr_objcConst+0x20;
            struct wj_data_64_point * r_baseMethods_data = (struct wj_data_64_point*)(addr_objcConst_baseMethods);

            struct wj_method64List_head* methodListHead = (struct wj_method64List_head*)((uint32_t)r_baseMethods_data->point + (uint64_t)mh);
            
            uint64_t addr_imp_method = find_impPoint_with_methodListHead(mh,methodListHead,methName);
            return addr_imp_method;
            
        }
        
    }

    return 0;
}




@end
