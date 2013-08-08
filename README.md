# CTidy

Tidy library with sanitize functionality.

## Usage

Convert HTML data to valid XHTML:

````objc
NSString* html = @"<html><body><br><br><p>Hello</p></body></html>";
NSString* xhtml = [[CTidy tidy] tidyHTMLString:html
                                      encoding:@"UTF8"
                                      sanitize:NO
                                         error:&error];
NSLog(@"%@", xhtml);
````

Output:

````html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta name="generator" content=
"HTML Tidy for Mac OS X (vers 31 October 2006 - Apple Inc. build 15.4), see www.w3.org" />
<title></title>
</head>
<body>
<br />
<br />
<p>Hello</p>
</body>
</html>
````

Convert HTML data to valid XHTML and perform Javascript sanitization:

````objc
NSString* html = @"<html><body><br><br><p>Hello</p></body></html>";
NSString* xhtml = [[CTidy tidy] tidyHTMLString:html
                                      encoding:@"UTF8"
                                      sanitize:YES
                                         error:&error];
NSLog(@"%@", xhtml);
````

## Credit

Based on [TouchXML](https://github.com/TouchCode/TouchXML)
Forked from [CTidy](https://github.com/siuying/CTidy)

## License

This code is licensed under the 2-clause BSD license ("Simplified BSD License" or "FreeBSD License") license. 

