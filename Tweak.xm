/* 
	Special thanks to Ian Beer of Google's ProjectZero!
	Blog Post: http://googleprojectzero.blogspot.com/2014/11/pwn4fun-spring-2014-safari-part-ii.html
	Copyright (c) 2020 Brandon Plank
*/

#import "IOKitLib.h"
#import <substrate.h>
#import <Foundation/Foundation.h>

int up_in_here(){
  static int seeded = 0;
  if(!seeded){
    srand(time(NULL));
    seeded = 1;
  }
  return !(rand() % 100);
}

void flip_bit(void* buf, size_t len){
  if (!len)
    return;
  size_t offset = rand() % len;
  ((uint8_t*)buf)[offset] ^= (0x01 << (rand() % 8));
}

static kern_return_t (*old_IOConnectCallMethod)(
	mach_port_t connection,
  uint32_t    selector,
  uint64_t   *input,
  uint32_t    inputCnt,
  void       *inputStruct,
  size_t      inputStructCnt,
  uint64_t   *output,
  uint32_t   *outputCnt,
  void       *outputStruct,
  size_t     *outputStructCntP);

kern_return_t fake_IOConnectCallMethod(
  mach_port_t connection,
  uint32_t    selector,
  uint64_t   *input,
  uint32_t    inputCnt,
  void       *inputStruct,
  size_t      inputStructCnt,
  uint64_t   *output,
  uint32_t   *outputCnt,
  void       *outputStruct,
  size_t     *outputStructCntP)
{
	bool didFuzz = 0;
	if (up_in_here())
	{
		didFuzz = 1;
		NSLog(@"[Kuzz] fake_IOConnectCallMethod called, flipping #1\n");
		flip_bit(input, sizeof(input) * inputCnt);
	}
	if (up_in_here())
	{
		didFuzz = 1;
		NSLog(@"[Kuzz] fake_IOConnectCallMethod called, flipping #2\n");
		flip_bit(inputStruct, inputStructCnt);
	}

	if (didFuzz)
	{
		NSMutableArray *caseData = [[NSMutableArray alloc] init];
		[caseData addObject:@"testcase"];
		[caseData addObject:@(selector)];

		NSLog(@"[Kuzz] TESTCASE = %@", caseData);
	}
	
	return old_IOConnectCallMethod(
		connection,
		selector,
		input,
		inputCnt,
		inputStruct,
		inputStructCnt,
		output,
		outputCnt,
		outputStruct,
		outputStructCntP);
}
/*
  Loads into all processes except SpringBoard and backboardd.
  The goal of kuzz is to trigger a non watchdogd panic.
*/
%ctor {
    if ([[[[NSProcessInfo processInfo] arguments] objectAtIndex:0] containsString:@"SpringBoard.app"]){
        NSLog(@"[Kuzz] Not loading kuzz into SpringBoard!");
    } else if ([[[[NSProcessInfo processInfo] arguments] objectAtIndex:0] containsString:@"backboardd"]){
        NSLog(@"[Kuzz] Not loading kuzz into backboardd!");
    } else {
        MSHookFunction((int *)&IOConnectCallMethod, (int *)&fake_IOConnectCallMethod, (void **)&old_IOConnectCallMethod);
    }
}
