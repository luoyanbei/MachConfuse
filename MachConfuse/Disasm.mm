//
//  Disasm.m
//  MachConfuse
//
//  Created by wangjun1 on 2021/8/12.
//  Copyright © 2021 ldzspace. All rights reserved.
//

#import "Disasm.h"
#include "capstone.h"
#include "platform.h"

#define TAB_WIDTH 10
using namespace std;


@implementation Disasm


-(void)disASM:(void *)fileBuff{
        
    uint32_t location = 0x631c;
    uint32_t length = 4;
    char * ot_sect = (char*)fileBuff + location;//二进制文件的起始地址+代码段__text的偏移 = 代码段的起始地址
    uint32_t ot_left = 0x6D1C0;//是size;
    uint64_t ot_addr = 0x10000631C;//4294992668;
    
    csh cs_handle;
    cs_insn *cs_insn = NULL;
    size_t disasm_count = 0;
    cs_err cserr;
    /* open capstone */
    cs_arch target_arch = CS_ARCH_ARM64;
    cs_mode target_mode = CS_MODE_ARM;
    
    
    //    if ( (cserr = cs_open(target_arch, target_mode, &cs_handle)) != CS_ERR_OK )
    if (cs_open(target_arch, target_mode, &cs_handle))
    {
        NSLog(@"Failed to initialize Capstone: %d, %s.", cserr, cs_strerror(cs_errno(cs_handle)));
        return ;
    }
    
    /* enable detail - we need fields available in detail field */
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(cs_handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    
    /* disassemble the whole section */
    /* this will fail if we have data in code or jump tables because Capstone stops when it can't disassemble */
    /* a bit of a problem with most binaries :( */
    /* XXX: parse data in code section to partially solve this */
    disasm_count = cs_disasm(cs_handle, (const uint8_t *)ot_sect, ot_left, ot_addr, 0, &cs_insn);// ot_left 是size, ot_addr 是 Address,
    NSLog(@"Disassembled %lu instructions.", disasm_count);
    
    uint32_t fileOffset = location;
    for (size_t i = 0; i < disasm_count; i++)
    {
        /* XXX: replace this bytes retrieval with Capstone internal data since it already contains this info */
        NSRange range = NSMakeRange(fileOffset,0);
        NSString * lastReadHex;
        /* format the disassembly output using Capstone strings */
        NSString *asm_string = [NSString stringWithFormat:@"%-10s\t%s", cs_insn[i].mnemonic, cs_insn[i].op_str];
        /* advance to next instruction */
        fileOffset += cs_insn[i].size;
        
        printf("%s\n",[asm_string UTF8String]);
        
    }
    cs_free(cs_insn, disasm_count);
    cs_close(&cs_handle);
    
    
}

/*
 
 offset: 是macho中的地址偏移
 size：是代码块的大小,必须是4的倍数，一条汇编是4
 addr: 是Section64 Header(__text)的Address + offset
 */
-(NSArray *)disAsmWithBuff:(void *)fileBuff offset:(uint32_t)offset size:(uint32_t)size addr:(uint64_t)addr{
        
    char * ot_sect = (char*)fileBuff + offset;//二进制文件的起始地址+代码段__text的偏移 = 代码段的起始地址
    uint32_t ot_left = size;//0x6D1C0;//是size;
    uint64_t ot_addr = addr;//0x10000631C;//4294992668;
    
    csh cs_handle;
    cs_insn *cs_insn = NULL;
    size_t disasm_count = 0;
    cs_err cserr;
    /* open capstone */
    cs_arch target_arch = CS_ARCH_ARM64;
    cs_mode target_mode = CS_MODE_ARM;
    
    
    if ( (cserr = cs_open(target_arch, target_mode, &cs_handle)) != CS_ERR_OK )
    {
        NSLog(@"Failed to initialize Capstone: %d, %s.", cserr, cs_strerror(cs_errno(cs_handle)));
        return nil;
    }
    
    /* enable detail - we need fields available in detail field */
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(cs_handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    
    /* disassemble the whole section */
    /* this will fail if we have data in code or jump tables because Capstone stops when it can't disassemble */
    /* a bit of a problem with most binaries :( */
    /* XXX: parse data in code section to partially solve this */
    disasm_count = cs_disasm(cs_handle, (const uint8_t *)ot_sect, ot_left, ot_addr, 0, &cs_insn);// ot_left 是size, ot_addr 是 Address,
//    NSLog(@"Disassembled %lu instructions.", disasm_count);
    
    uint32_t fileOffset = offset;
    
    NSMutableArray * result = [NSMutableArray array];
    for (size_t i = 0; i < disasm_count; i++)
    {
        /* XXX: replace this bytes retrieval with Capstone internal data since it already contains this info */
        NSRange range = NSMakeRange(fileOffset,0);
        NSString * lastReadHex;
        /* format the disassembly output using Capstone strings */
        NSString * tmp_insn = [NSString stringWithUTF8String:cs_insn[i].op_str];
        tmp_insn = [tmp_insn stringByReplacingOccurrencesOfString:@" " withString:@""];
        
        NSString *asm_string = [NSString stringWithFormat:@"%s %@", cs_insn[i].mnemonic, tmp_insn];
        /* advance to next instruction */
        fileOffset += cs_insn[i].size;
//        printf("%s\n",[asm_string UTF8String]);
        [result addObject:asm_string];
    }
    cs_free(cs_insn, disasm_count);
    cs_close(&cs_handle);
    
    return result;
}




@end
