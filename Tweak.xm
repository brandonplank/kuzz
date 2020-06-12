/* 
	Special thanks to Ian Beer of Google's ProjectZero!
	Blog Post: http://googleprojectzero.blogspot.com/2014/11/pwn4fun-spring-2014-safari-part-ii.html
	Copyright (c) 2020 Brandon Plank
*/

#import "IOKitLib.h"
#import <substrate.h>
#include <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <mach/mach_types.h>
#include <mach/mach_host.h>
#include <getopt.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <ctype.h>
#import <mach/mach.h>
#import <sys/stat.h>
#import <sys/utsname.h>
#import <dlfcn.h>

#define fileThere(file) [[NSFileManager defaultManager] fileExistsAtPath:@(file)]

#define removeFile(file) if (fileThere(file)) {\
[[NSFileManager defaultManager]  removeItemAtPath:@(file) error:NULL]; \
}

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
	if (up_in_here()){
		didFuzz = 1;
		NSLog(@"[kuzz] fake_IOConnectCallMethod called, flipping #1\n");
		flip_bit(input, sizeof(input) * inputCnt);
	}
	if (up_in_here()){
		didFuzz = 1;
		NSLog(@"[kuzz] fake_IOConnectCallMethod called, flipping #2\n");
		flip_bit(inputStruct, inputStructCnt);
	}

	if (didFuzz){
		NSMutableArray *caseData = [[NSMutableArray alloc] init];
		[caseData addObject:@"testcase"];
		[caseData addObject:@(selector)];

		NSLog(@"[kuzz] TESTCASE = %@", caseData);
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


@interface UIStatusBarWindow : UIWindow
-(void)tapping; //from %new
@end

%hook UIStatusBarWindow
- (instancetype)initWithFrame:(CGRect)frame {
    self = %orig;

    UITapGestureRecognizer *tapRecognizer = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(tapping)]; //(tapping) will be used as a void down in the %new
    tapRecognizer.numberOfTapsRequired = 3; // 3 taps 
    tapRecognizer.cancelsTouchesInView = NO; //a safe way of adding a gesture, so that it doesn't break other gestures in the view.
    [self addGestureRecognizer:tapRecognizer];  //add that tap gesture

    return self;
}
%new // new method
-(void)tapping {
    UIAlertView *ac = [[UIAlertView alloc] initWithTitle:@"kuzz" message:@"Are you sure you want to fuzz?\nMost things will stop to work including apps." delegate:self cancelButtonTitle:@"No" otherButtonTitles:@"Yes", nil];
    [ac show];
}
%new
- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
    if (buttonIndex == 1) {
        NSString *str = @"yes";
        [str writeToFile:@"/var/mobile/Documents/kuzz.txt" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else {
        NSString *str = @"no";
        [str writeToFile:@"/var/mobile/Documents/kuzz.txt" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}
%end

%ctor {
    if (!fileThere("/var/mobile/Documents/kuzz.txt")){
      close(open("/var/mobile/Documents/kuzz.txt", O_CREAT));
      NSString *str = @"no";
      [str writeToFile:@"/var/mobile/Documents/kuzz.txt" atomically:YES encoding:NSUTF8StringEncoding error:nil];
      chmod("/var/mobile/Documents/kuzz.txt", 777);
      chown("/var/mobile/Documents/kuzz.txt",501, 501);
    }
    if ([[[[NSProcessInfo processInfo] arguments] objectAtIndex:0] containsString:@"SpringBoard.app"]){
        NSLog(@"[kuzz] Not loading kuzz into SpringBoard!, but we are going to make a saftey switch!");
    } else if ([[[[NSProcessInfo processInfo] arguments] objectAtIndex:0] containsString:@"backboardd"]){
        NSLog(@"[kuzz] Not loading kuzz into backboardd!");
    } else if ([[[[NSProcessInfo processInfo] arguments] objectAtIndex:0] containsString:@"biometrickitd"]){
        NSLog(@"[kuzz] Not loading into biometrickitd");
    } else if ([[[[NSProcessInfo processInfo] arguments] objectAtIndex:0] containsString:@"Sileo.app"]){
        NSLog(@"[kuzz] Not loading into Sileo");
    } else if ([[[[NSProcessInfo processInfo] arguments] objectAtIndex:0] containsString:@"Cydia.app"]){
        NSLog(@"[kuzz] Not loading into Cydia");
    } else if ([[[[NSProcessInfo processInfo] arguments] objectAtIndex:0] containsString:@"Zebra.app"]){
        NSLog(@"[kuzz] Not loading into Zebra");
    } else {
        NSString* path = @"/var/mobile/Documents/kuzz.txt";
        NSError* error = nil;
        NSString* content = [NSString stringWithContentsOfFile:path
                                              encoding:NSUTF8StringEncoding
                                                 error:&error];
        if (error){
          NSLog(@"[kuzz] Oh no :( error with file");
        } else {
            NSLog(@"[kuzz] Content of settings file = %@", content);
            if (strcmp([content UTF8String], "yes")==0){
              MSHookFunction((int *)&IOConnectCallMethod, (int *)&fake_IOConnectCallMethod, (void **)&old_IOConnectCallMethod);
            } else {
              NSLog(@"[kuzz] Not loading into anything");
            }
        }
    }
}
