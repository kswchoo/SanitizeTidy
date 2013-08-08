//
//  CTidyTest.m
//  CTidyTest
//
//  Created by Kevin on 8/8/13.
//  Copyright (c) 2013 Ignition Soft Limited. All rights reserved.
//

#import "SanitizeTidyTest.h"
#import "SanitizeTidy.h"
#import "sanitizer.h"

@implementation SanitizeTidyTest

- (void)setUp
{
    [super setUp];
    
    // Set-up code here.
}

- (void)tearDown
{
    // Tear-down code here.
    
    [super tearDown];
}

- (void)testExample
{
    SanitizeTidy *ctidy = [[SanitizeTidy alloc] init];
    NSString *path = [[NSBundle bundleWithIdentifier:@"kr.pe.kswchoo.SanitizeTidyTest"] pathForResource:@"example" ofType:@"html"];
    
    
    NSString *originalHtml = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"ORIGINAL HTML\n----------\n%@\n----------", originalHtml);
    
    NSString *tidyHtml = [ctidy tidyHTMLString:originalHtml encoding:@"UTF8" sanitize:NO error:nil];
    NSLog(@"TIDY HTML\n----------\n%@\n----------", tidyHtml);
    
    NSString *sanitizedHtml = [ctidy tidyHTMLString:originalHtml encoding:@"UTF8" sanitize:YES error:nil];
    NSLog(@"SANITIZED HTML\n----------\n%@\n----------", sanitizedHtml);
    //STFail(@"Unit tests are not implemented yet in CTidyTest");
}

@end
