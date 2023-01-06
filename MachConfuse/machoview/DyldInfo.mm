/*
 *  DyldInfo.mm
 *  MachOView
 *
 *  Created by psaghelyi on 21/09/2010.
 *
 */

#include <string>
#include <vector>
#include <set>
#include <map>
#import <mach-o/loader.h>
#import "Common.h"
#import "DyldInfo.h"
//#import "DataController.h"

using namespace std;



//============================================================================
@implementation DyldInfo
{
    ReadWrite * readWrite;
    SegmentVector           segments;         // segment entries for 32-bit architectures
    Segment64Vector         segments_64;
}




- (BOOL)is64bit
{
    //  MATCH_STRUCT(mach_header,imageOffset);
    //  return ((mach_header->cputype & CPU_ARCH_ABI64) == CPU_ARCH_ABI64);
    return YES;
}

-(id)initWithFilePath:(NSString *)filepath {
    if (self = [super init])
    {
        readWrite = [[ReadWrite alloc] initWithFilePath:filepath];
    }
    return self;
}


- (NSDictionary *)createBindingClassrefs_location:(uint32_t)location
                                 length:(uint32_t)length
                            baseAddress:(uint64_t)baseAddress nodeType:(BindNodeType)nodeType segments:(Segment64Vector)segVector
{
    segments_64 = segVector;
    
    NSRange range = NSMakeRange(location,0);
    NSString * lastReadHex;
    
    NSMutableDictionary * resultDict = [NSMutableDictionary dictionary];
    //----------------------------
    
    BOOL isDone = NO;
    
    int32_t libOrdinal = 0;
    uint32_t type = 0;
    int64_t addend = 0;
    NSString * symbolName = nil;
    uint32_t symbolFlags = 0;
    
    uint32_t doBindLocation = location;
    
    uint64_t ptrSize = ([self is64bit] == NO ? sizeof(uint32_t) : sizeof(uint64_t));
    uint64_t address = baseAddress;
    
    while (NSMaxRange(range) < location + length && isDone == NO)
    {
        uint8_t byte = [readWrite read_int8:range lastReadHex:&lastReadHex];
        uint8_t opcode = byte & BIND_OPCODE_MASK;
        uint8_t immediate = byte & BIND_IMMEDIATE_MASK;
        
        switch (opcode)
        {
            case BIND_OPCODE_DONE:
                // The lazy bindings have one of these at the end of each bind.
                if (nodeType != NodeTypeLazyBind)
                {
                    isDone = YES;
                }
                
                doBindLocation = NSMaxRange(range);
                
                break;
                
            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                libOrdinal = immediate;
                
                break;
                
            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                
                libOrdinal = [readWrite read_uleb128:range lastReadHex:&lastReadHex];
                
                break;
                
            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            {
                // Special means negative
                if (immediate == 0)
                {
                    libOrdinal = 0;
                }
                else
                {
                    int8_t signExtended = immediate | BIND_OPCODE_MASK; // This sign extends the value
                    
                    libOrdinal = signExtended;
                }
                
            } break;
                
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                symbolFlags = immediate;
                
                symbolName = [readWrite read_string:range lastReadHex:&lastReadHex];
                
                break;
                
            case BIND_OPCODE_SET_TYPE_IMM:
                type = immediate;
                
                break;
                
            case BIND_OPCODE_SET_ADDEND_SLEB:
                addend = [readWrite read_sleb128:range lastReadHex:&lastReadHex];
                
                break;
                
            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            {
                uint32_t segmentIndex = immediate;
                
                uint64_t val = [readWrite read_uleb128:range lastReadHex:&lastReadHex];
                
                if (([self is64bit] == NO && segmentIndex >= segments.size()) ||
                    ([self is64bit] == YES && segmentIndex >= segments_64.size()))
                {
                    [NSException raise:@"Segment"
                                format:@"index is out of range %u", segmentIndex];
                }
                
                address = ([self is64bit] == NO ? segments.at(segmentIndex)->vmaddr
                           : segments_64.at(segmentIndex)->vmaddr) + val;//这个address就是代码段中 要加载的类的 地址，例如：0x1ca44 处的0x1000C6B28; segments_64.at(segmentIndex)->vmaddr)是 LC_SEGMENT_64(__DATA)的vm_address 0x100094000
            } break;
                
            case BIND_OPCODE_ADD_ADDR_ULEB:
            {
                
                uint64_t val = [readWrite read_uleb128:range lastReadHex:&lastReadHex];
                                
                address += val;//执行到这里
            } break;
                
            case BIND_OPCODE_DO_BIND:
            {
                [self bindAddress:address
                             type:type
                       symbolName:symbolName
                            flags:symbolFlags
                           addend:addend
                   libraryOrdinal:libOrdinal
                         nodeType:nodeType
                         location:doBindLocation
                          ptrSize:ptrSize];
                
                
                
                [resultDict setObject:symbolName forKey:[NSString stringWithFormat:@"%llx",address]];
                
                doBindLocation = NSMaxRange(range);
                
                address += ptrSize;
            } break;
                
            case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            {
                
                uint32_t startNextBind = NSMaxRange(range);
                
                uint64_t val = [readWrite read_uleb128:range lastReadHex:&lastReadHex];
                
                [self bindAddress:address
                             type:type
                       symbolName:symbolName
                            flags:symbolFlags
                           addend:addend
                   libraryOrdinal:libOrdinal
                         nodeType:nodeType
                         location:doBindLocation
                          ptrSize:ptrSize];
                [resultDict setObject:symbolName forKey:[NSString stringWithFormat:@"%llx",address]];

                
                doBindLocation = startNextBind;
                
                address += ptrSize + val;
            } break;
                
            case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            {
                uint32_t scale = immediate;
                
                
                [self bindAddress:address
                             type:type
                       symbolName:symbolName
                            flags:symbolFlags
                           addend:addend
                   libraryOrdinal:libOrdinal
                         nodeType:nodeType
                         location:doBindLocation
                          ptrSize:ptrSize];
                [resultDict setObject:symbolName forKey:[NSString stringWithFormat:@"%llx",address]];

                doBindLocation = NSMaxRange(range);
                
                address += ptrSize + scale * ptrSize;
            } break;
                
            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            {
                
                uint32_t startNextBind = NSMaxRange(range);
                
                uint64_t count = [readWrite read_uleb128:range lastReadHex:&lastReadHex];
                
                
                uint64_t skip = [readWrite read_uleb128:range lastReadHex:&lastReadHex];
                
                
                
                for (uint64_t index = 0; index < count; index++)
                {
                    [self bindAddress:address
                                 type:type
                           symbolName:symbolName
                                flags:symbolFlags
                               addend:addend
                       libraryOrdinal:libOrdinal
                             nodeType:nodeType
                             location:doBindLocation
                              ptrSize:ptrSize];
                    [resultDict setObject:symbolName forKey:[NSString stringWithFormat:@"%llx",address]];

                    doBindLocation = startNextBind;
                    
                    address += ptrSize + skip;
                }
            } break;
                
            default:
                [NSException raise:@"Bind info" format:@"Unknown opcode (%u %u)",
                 ((uint32_t)-1 & opcode), ((uint32_t)-1 & immediate)];
        }
    }
    
    return resultDict;
}
//-----------------------------------------------------------------------------

- (void)bindAddress:(uint64_t)address
               type:(uint32_t)type
         symbolName:(NSString *)symbolName
              flags:(uint32_t)flags
             addend:(int64_t)addend
     libraryOrdinal:(int32_t)libOrdinal
           nodeType:(BindNodeType)nodeType
           location:(uint32_t)location
            ptrSize:(uint32_t)ptrSize
{
    if([symbolName containsString:@"_OBJC_CLASS_$_"]){
        NSLog(@"oc类：%@",symbolName);
    }
    
    NSString * bindInfo = [NSString stringWithFormat:@"classrefs address:0x%lx (%@)",address,symbolName];
    NSLog(@"bindInfo:\n%@",bindInfo);
    
    
}

@end
