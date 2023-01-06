//
//  MachOpt.h
//  MachConfuse
//
//  Created by wangjun1 on 2021/8/16.
//  Copyright © 2021 ldzspace. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <Vector>

NS_ASSUME_NONNULL_BEGIN

@interface MachOpt : NSObject
void dumpSection_data_objc_classrefs(const struct mach_header *mh, char rpath[4096], char npath[4096], int outfd);
std::vector<struct segment_command_64 const *> findAllSegment(const struct mach_header *mh);

uint64_t getUInt64fromHex(char const *str);

char * find_class_from_objc_classrefs(const struct mach_header *mh, char const *str);

uint64_t find_implementation_by_className_methName(const struct mach_header *mh,const char* className, const char * methName);

struct section_64 const * findSection64ByName(const struct mach_header *mh,char const *sectnamechar ,char const *segnamet);

@end

NS_ASSUME_NONNULL_END
