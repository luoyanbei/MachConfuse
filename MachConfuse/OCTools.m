//
//  OCTools.m
//  MachConfuse
//
//  Created by King on 2018/7/9.
//  Copyright © 2018年 ldzspace. All rights reserved.
//

#import "OCTools.h"
#include <mach-o/loader.h>

@implementation OCTools

+(NSString *)getNameForCommand:(uint32_t)cmd
{
    switch(cmd)
    {
        default:                      return @"???";
        case LC_SEGMENT:              return @"LC_SEGMENT";
        case LC_SYMTAB:               return @"LC_SYMTAB";
        case LC_SYMSEG:               return @"LC_SYMSEG";
        case LC_THREAD:               return @"LC_THREAD";
        case LC_UNIXTHREAD:           return @"LC_UNIXTHREAD";
        case LC_LOADFVMLIB:           return @"LC_LOADFVMLIB";
        case LC_IDFVMLIB:             return @"LC_IDFVMLIB";
        case LC_IDENT:                return @"LC_IDENT";
        case LC_FVMFILE:              return @"LC_FVMFILE";
        case LC_PREPAGE:              return @"LC_PREPAGE";
        case LC_DYSYMTAB:             return @"LC_DYSYMTAB";
        case LC_LOAD_DYLIB:           return @"LC_LOAD_DYLIB";
        case LC_ID_DYLIB:             return @"LC_ID_DYLIB";
        case LC_LOAD_DYLINKER:        return @"LC_LOAD_DYLINKER";
        case LC_ID_DYLINKER:          return @"LC_ID_DYLINKER";
        case LC_PREBOUND_DYLIB:       return @"LC_PREBOUND_DYLIB";
        case LC_ROUTINES:             return @"LC_ROUTINES";
        case LC_SUB_FRAMEWORK:        return @"LC_SUB_FRAMEWORK";
        case LC_SUB_UMBRELLA:         return @"LC_SUB_UMBRELLA";
        case LC_SUB_CLIENT:           return @"LC_SUB_CLIENT";
        case LC_SUB_LIBRARY:          return @"LC_SUB_LIBRARY";
        case LC_TWOLEVEL_HINTS:       return @"LC_TWOLEVEL_HINTS";
        case LC_PREBIND_CKSUM:        return @"LC_PREBIND_CKSUM";
        case LC_LOAD_WEAK_DYLIB:      return @"LC_LOAD_WEAK_DYLIB";
        case LC_SEGMENT_64:           return @"LC_SEGMENT_64";
        case LC_ROUTINES_64:          return @"LC_ROUTINES_64";
        case LC_UUID:                 return @"LC_UUID";
        case LC_RPATH:                return @"LC_RPATH";
        case LC_CODE_SIGNATURE:       return @"LC_CODE_SIGNATURE";
        case LC_SEGMENT_SPLIT_INFO:   return @"LC_SEGMENT_SPLIT_INFO";
        case LC_REEXPORT_DYLIB:       return @"LC_REEXPORT_DYLIB";
        case LC_LAZY_LOAD_DYLIB:      return @"LC_LAZY_LOAD_DYLIB";
        case LC_ENCRYPTION_INFO:      return @"LC_ENCRYPTION_INFO";
        case LC_ENCRYPTION_INFO_64:   return @"LC_ENCRYPTION_INFO_64";
        case LC_DYLD_INFO:            return @"LC_DYLD_INFO";
        case LC_DYLD_INFO_ONLY:       return @"LC_DYLD_INFO_ONLY";
        case LC_LOAD_UPWARD_DYLIB:    return @"LC_LOAD_UPWARD_DYLIB";
        case LC_VERSION_MIN_MACOSX:   return @"LC_VERSION_MIN_MACOSX";
        case LC_VERSION_MIN_IPHONEOS: return @"LC_VERSION_MIN_IPHONEOS";
        case LC_FUNCTION_STARTS:      return @"LC_FUNCTION_STARTS";
        case LC_DYLD_ENVIRONMENT:     return @"LC_DYLD_ENVIRONMENT";
        case LC_MAIN:                 return @"LC_MAIN";
        case LC_DATA_IN_CODE:         return @"LC_DATA_IN_CODE";
        case LC_SOURCE_VERSION:       return @"LC_SOURCE_VERSION";
        case LC_DYLIB_CODE_SIGN_DRS:  return @"LC_DYLIB_CODE_SIGN_DRS";
        case LC_LINKER_OPTION:        return @"LC_LINKER_OPTION";
        case LC_LINKER_OPTIMIZATION_HINT: return @"LC_LINKER_OPTIMIZATION_HINT";
    }
}


@end
