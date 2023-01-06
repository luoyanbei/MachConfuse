//
//  Disasm.h
//  MachConfuse
//
//  Created by wangjun1 on 2021/8/12.
//  Copyright © 2021 ldzspace. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface Disasm : NSObject
-(void)disASM:(void *)fileBuff;
-(NSArray *)disAsmWithBuff:(void *)fileBuff offset:(uint32_t)offset size:(uint32_t)size addr:(uint64_t)addr;

@end

NS_ASSUME_NONNULL_END
