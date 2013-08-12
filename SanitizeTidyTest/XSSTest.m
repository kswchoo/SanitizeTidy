//
//  XSSTest.m
//  XSSTest
//
//  This test case tests many known XSS attacks are properly stripped by
//  SanitizeTidy.
//  See https://www.owasp.org/index.php?title=XSS_Filter_Evasion_Cheat_Sheet
//
//  Created by Kevin on 8/8/13.
//  Copyright (c) 2013 Sungwoo Choo. All rights reserved.
//

#import "XSSTest.h"
#import "SanitizeTidy.h"
#import "sanitizer.h"

@implementation XSSTest

- (void)testNoFilterEvasion
{
    NSString *result = [self doTidy:@"<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>"];
    STAssertTrue([result rangeOfString:@"script"].location == NSNotFound, @"No Filter Evasion");
}

- (void)testImageXssUsingThejavaScriptDirective
{
    NSString *result = [self doTidy:@"<IMG SRC=\"javascript:alert('XSS');\">"];
    STAssertTrue([result rangeOfString:@"javascript"].location == NSNotFound, @"Image XSS using the JavaScript direvtive");
}

- (void)testNoQuotesAndNoSemicolon
{
    NSString *result = [self doTidy:@"<IMG SRC=javascript:alert('XSS')>"];
    STAssertTrue([result rangeOfString:@"javascript"].location == NSNotFound, @"No quotes and no semicolon");
}

- (void)testCaseInsensitiveXssAttackVector
{
    NSString *result = [self doTidy:@"<IMG SRC=JaVaScRiPt:alert('XSS')>"];
    STAssertTrue([result rangeOfString:@"javascript"].location == NSNotFound, @"Case insensitive XSS attack vector");
}

- (void)testHtmlEntities
{
    NSString *result = [self doTidy:@"<IMG SRC=javascript:alert(\"XSS\")>"];
    STAssertTrue([result rangeOfString:@"javascript"].location == NSNotFound, @"HTML entities");
}

- (void)testGraveAccentObfuscation
{
    NSString *result = [self doTidy:@"<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`"];
    STAssertTrue([result rangeOfString:@"javascript"].location == NSNotFound, @"Grave accent obfuscation");
}

// TODO(kevin) : Add more and more test cases here...

- (NSString *)doTidy:(NSString *)html {
    SanitizeTidy *ctidy = [SanitizeTidy new];
    return [ctidy tidyHTMLString:html encoding:@"UTF8" sanitize:YES error:nil];
}

@end
