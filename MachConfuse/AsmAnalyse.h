//
//  AsmAnalyse.h
//  MachConfuse
//
//  Created by wangjun1 on 2021/8/13.
//  Copyright © 2021 ldzspace. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AsmAnalyse : NSObject

-(NSString *)analyseSingleAsm:(NSString *)singleAsm;
-(NSArray *)analyseAsmArray:(NSArray *)Asms;
-(NSArray *)gainArrayFromSingleAsm:(NSString *)singleAsm;
-(int)findAsmArrayEndIndex:(NSArray *)asms;

@end

NS_ASSUME_NONNULL_END
