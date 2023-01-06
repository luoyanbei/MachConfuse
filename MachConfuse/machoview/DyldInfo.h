/*
 *  DyldInfo.h
 *  MachOView
 *
 *  Created by psaghelyi on 21/09/2010.
 *
 */

//#import "MachOLayout.h"
#import <Foundation/Foundation.h>
#import "ReadWrite.h"

typedef std::vector<struct segment_command const *>       SegmentVector;
typedef std::vector<struct segment_command_64 const *>    Segment64Vector;

@interface DyldInfo : NSObject

enum BindNodeType {NodeTypeBind, NodeTypeWeakBind, NodeTypeLazyBind};

//@property (nonatomic)                   NSString *      fileName;
//@property (nonatomic)                   NSMutableData * fileData;
//@property (nonatomic)                   NSMutableData * realData;

//@property(nonatomic, strong) ReadWrite * readWrite;

-(instancetype)initWithFilePath:(NSString *)filepath;

- (NSDictionary *)createBindingClassrefs_location:(uint32_t)location
     length:(uint32_t)length baseAddress:(uint64_t)baseAddress nodeType:(BindNodeType)nodeType segments:(Segment64Vector)segVector;


@end
