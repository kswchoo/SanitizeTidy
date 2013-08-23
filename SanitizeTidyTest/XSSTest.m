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
    STAssertTrue([result rangeOfString:@"alert"].location == NSNotFound, @"Image XSS using the JavaScript direvtive");
}

- (void)testNoQuotesAndNoSemicolon
{
    NSString *result = [self doTidy:@"<IMG SRC=javascript:alert('XSS')>"];
    STAssertTrue([result rangeOfString:@"alert"].location == NSNotFound, @"No quotes and no semicolon");
}

- (void)testCaseInsensitiveXssAttackVector
{
    NSString *result = [self doTidy:@"<IMG SRC=JaVaScRiPt:alert('XSS')>"];
    STAssertTrue([result rangeOfString:@"alert"].location == NSNotFound, @"Case insensitive XSS attack vector");
}

- (void)testHtmlEntities
{
    NSString *result = [self doTidy:@"<IMG SRC=javascript:alert(\"XSS\")>"];
    STAssertTrue([result rangeOfString:@"alert"].location == NSNotFound, @"HTML entities");
}

- (void)testGraveAccentObfuscation
{
    NSString *result = [self doTidy:@"<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`"];
    STAssertTrue([result rangeOfString:@"alert"].location == NSNotFound, @"Grave accent obfuscation");
}

- (void)testMalformedATags
{
    NSString *result = [self doTidy:@"<a onmouseover=\"alert(document.cookie)\">xxs link</a>"];
    STAssertEquals([result rangeOfString:@"alert"].location, NSNotFound, @"Malofrmed A tags");
}

- (void)testMalformedImgTags
{
    NSString *result = [self doTidy:@"<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>"];
    STAssertEquals([result rangeOfString:@"alert"].location, NSNotFound, @"Malofrmed Img tags");
    
}

- (void)testFromCharCode
{
    NSString *result = [self doTidy:@"<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>"];
    STAssertEquals([result rangeOfString:@"alert"].location, NSNotFound, @"FromCharCode");
}

- (void)testDefaultSrcTagToGetPastFiltersTahtCheckSrcDomain
{
    NSString *result = [self doTidy:@"<IMG SRC=# onmouseover=\"alert('xss')\">"];
    STAssertEquals([result rangeOfString:@"alert"].location, NSNotFound, @"Default SRC tag to get past filters that check SRC domain");
}

- (void)testDefaultSrcTagByLeavingItOutEntirely
{
    NSString *result = [self doTidy:@"<IMG onmouseover=\"alert('xss')\">"];
    STAssertEquals([result rangeOfString:@"alert"].location, NSNotFound, @"Default SRC tag by leaving it out entirely");
}

- (void)testUtf8UnicodeEncoding
{
    NSString *result = [self doTidy:@"<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>"];
    STAssertEquals([result rangeOfString:@"alert"].location, NSNotFound, @"UTF8 Unicode encoding");
}

- (void)testLongUtf8UnicodeEncodingWithoutSemicolons
{
    NSString *result = [self doTidy:@"<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>"];
    STAssertEquals([result rangeOfString:@"alert"].location, NSNotFound, @"Long UTF8 Unicode encoding without semocolons");
}

- (void)testHexEncodingWithoutSemicolons
{
    NSString *result = [self doTidy:@"<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>"];
    STAssertEquals([result rangeOfString:@"alert"].location, NSNotFound, @"Hex encoding without semicolons");
}

- (void)testEmbeddedTab
{
    NSString *result = [self doTidy:@"<IMG SRC=\"jav	ascript:alert('XSS');\">"];
    STAssertEquals([result rangeOfString:@"javascript"].location, NSNotFound, @"Embedded tab");
}

- (void)testEmbeddedEncodedTab
{
    NSString *result = [self doTidy:@"<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">"];
    STAssertEquals([result rangeOfString:@"javascript"].location, NSNotFound, @"Embedded Encoded tab");
}

- (void)testEmbeddedNewlineToBreakUpXss
{
    NSString *result = [self doTidy:@"<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">"];
    STAssertEquals([result rangeOfString:@"javascript"].location, NSNotFound, @"Embedded newline to break up XSS");
}

- (void)testEmbeddedCarriageReturnToBreakUpXss
{
    NSString *result = [self doTidy:@"<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">"];
    STAssertEquals([result rangeOfString:@"javascript"].location, NSNotFound, @"Embedded carriage return to break up XSS");
}

- (void)testNullBreaksUpJavaScriptDirective
{
    NSString *result = [self doTidy:@"<IMG SRC=java\0script:alert(\"XSS\")>"];
    STAssertEquals([result rangeOfString:@"javascript"].location, NSNotFound, @"Null breaks up JavaScript directive");
}

- (void)testSpacesAndMetaCharsBeforeTheJavaScriptInImagesForXss
{
    NSString *result = [self doTidy:@"<IMG SRC=\" &#14;  javascript:alert('XSS');\">"];
    STAssertEquals([result rangeOfString:@"javascript"].location, NSNotFound, @"Spaces and meta chars before the JavaScript in images for XSS");
}

- (void)testNonAlphaNonDigitXss1
{
    NSString *result = [self doTidy:@"<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>"];
    STAssertEquals([result rangeOfString:@"script"].location, NSNotFound, @"Non-alpha-non-digit XSS 1");
}

- (void)testNonAlphaNonDigitXss2
{
    NSString *result = [self doTidy:@"<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>"];
    STAssertEquals([result rangeOfString:@"script"].location, NSNotFound, @"Non-alpha-non-digit XSS 2");
}

- (void)testNonAlphaNonDigitXss3
{
    NSString *result = [self doTidy:@"<SCRIPT/SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>"];
    STAssertEquals([result rangeOfString:@"script"].location, NSNotFound, @"Non-alpha-non-digit XSS 3");
}

- (void)testExtraneousOpenBrackets
{
    NSString *result = [self doTidy:@"<<SCRIPT>alert(\"XSS\");//<</SCRIPT>"];
    STAssertEquals([result rangeOfString:@"script"].location, NSNotFound, @"Extraneous open brackets");
}

- (void)testDataImgSrc
{
    NSString *result = [self doTidy:@"<img src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnb2JqZWN0X3NjcmlwdF9hbGVydCcpPC9zY3JpcHQ+\" width=0 height=0> "];
    STAssertEquals([result rangeOfString:@"script"].location, NSNotFound, @"Text/html");
}

- (void)testIFrame
{
    NSString *result = [self doTidy:@"<iframe src=\"http://www.daum.net/\">"];
    STAssertEquals([result rangeOfString:@"iframe"].location, NSNotFound, @"iframe");
}

//- (void)testEmbedStrip
//{
//    NSString *result = [self doTidy:@"<embed src=\"http://www.naver.com/\" height=\"100\">"];
//    STAssertEquals([result rangeOfString:@"embed"].location, NSNotFound, @"testEmbedStrip");
//}

- (void)testEmbedSrcStrip
{
    NSString *result = [self doTidy:@"<embed src=\"http://www.naver.com/\" height=\"100\">"];
    STAssertEquals([result rangeOfString:@"src"].location, NSNotFound, @"testEmbedSrcStrip");
}

- (void)testOnSomething
{
    NSString *result = [self doTidy:@"<embed onsomething=\"http://www.naver.com/\" height=\"100\">"];
    STAssertEquals([result rangeOfString:@"onsomething"].location, NSNotFound, @"testOnSomething");
}

- (void)testFileUrl
{
    NSString *result = [self doTidy:@"<a href=\"file:///abc.txt\">"];
    STAssertEquals([result rangeOfString:@"file:"].location, NSNotFound, @"testFileUrl");
}


// TODO(kevin) : Add more and more test cases here...

- (NSString *)doTidy:(NSString *)html {
    SanitizeTidy *ctidy = [SanitizeTidy new];
    return [ctidy tidyHTMLString:html encoding:@"UTF8" sanitize:YES error:nil];
}

@end
