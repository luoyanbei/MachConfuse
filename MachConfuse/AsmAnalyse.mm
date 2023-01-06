//
//  AsmAnalyse.m
//  MachConfuse
//
//  Created by wangjun1 on 2021/8/13.
//  Copyright © 2021 ldzspace. All rights reserved.
//

#import "AsmAnalyse.h"

@implementation AsmAnalyse

-(NSArray *)analyseAsmArray:(NSArray *)asms{
    NSMutableArray * addrArray = [NSMutableArray array];
    for(NSString * tmp_asm in asms){
        NSString * addrStr = [self analyseSingleAsm:tmp_asm];
        if(addrStr){
            [addrArray addObject:[addrStr stringByReplacingOccurrencesOfString:@"#0x" withString:@""]];
        }
    }
    
    NSLog(@"地址数组：\n%@",addrArray);
    return addrArray;
}


-(NSArray *)gainArrayFromSingleAsm:(NSString *)singleAsm {
    NSArray *arr = [singleAsm componentsSeparatedByString:@" "];//通过空格符来分隔字符串
    NSString * instruct = @"";
    if([arr count]>0){
        instruct = arr[0];
    }
    
    NSString * optStr = @"";
    if([arr count]>1){
        optStr = arr[1];
    }
    
    NSArray *arr_opt = [optStr componentsSeparatedByString:@","];
    
    NSMutableArray * result = [NSMutableArray array];
    [result addObject:instruct];
    
    for(NSString * opt in arr_opt){
        if(opt && ![opt isEqualToString:@""]){
            [result addObject:opt];
        }
    }
//    NSLog(@"%@",arr_opt);
    return result;

}


-(NSString *)analyseSingleAsm:(NSString *)singleAsm{
    NSArray * opt_array = [self gainArrayFromSingleAsm:singleAsm];
    NSString * result = nil;
    
    
    if([opt_array count]==3){
        if([opt_array[0] isEqualToString:@"ldr"] && ([opt_array[1] isEqualToString:@"x0"])){
            NSLog(@"目标：%@ %@,%@",opt_array[0],opt_array[1],opt_array[2]);
            result = opt_array[2];
        }
    }
    
    if([opt_array count]==1){
        if([opt_array[0] isEqualToString:@"ret"]){
            NSLog(@"目标结束：%@",opt_array[0]);
        }
    }
    
    return result;
}

-(BOOL)isRetAsm:(NSString *)singleAsm{
    
    NSArray * opt_array = [self gainArrayFromSingleAsm:singleAsm];
    
    if([opt_array count]==1){
        if([opt_array[0] isEqualToString:@"ret"]){
            NSLog(@"目标结束1：%@",singleAsm);
            return YES;
        }
    }
    
//    if([opt_array count]==2){
//        if([opt_array[0] isEqualToString:@"b"]){
//            NSLog(@"目标结束2：%@",singleAsm);
//            return YES;
//        }
//    }
    
//    //结束标志 STP             X29, X30
//    if([opt_array count]==4){
//        if([opt_array[0] isEqualToString:@"stp"] && ([opt_array[1] isEqualToString:@"x29"]) && ([opt_array[2] isEqualToString:@"x30"])){
//            NSLog(@"结束：%@",singleAsm);
//            return YES;
//        }
//    }
        
    return NO;
}

-(int)findAsmArrayEndIndex:(NSArray *)asms
{
    int count = (int)[asms count];
    for(int i=0; i<count; i++){
        NSString * tmp_asm = asms[i];
        BOOL isEnd = [self isRetAsm:tmp_asm];
        if(isEnd){
            //遇到结束标记
            return i;
        }
    }
    return -1;//没有找到结束标记“ret”
}



@end
