//
//  sanitizer.c
//  CTidy
//
//  Created by Kevin on 8/8/13.
//  Copyright (c) 2013 NAVER Corp. All rights reserved.
//  Author(s) : Sungwoo Choo
//

#include <stdio.h>
#include "tidy-int.h"
#include "clean.h"
#include "lexer.h"
#include "parser.h"
#include "attrs.h"
#include "message.h"
#include "tmbstr.h"
#include "utf8.h"
#include "errno.h"


int tidyDocSanitize( TidyDocImpl* doc );
Node* dropScripts(TidyDocImpl* doc, Node* node);
Node* dropComments(TidyDocImpl* doc, Node* node);
Node* dropObject(TidyDocImpl* doc, Node* node);
Node* dropIframe(TidyDocImpl* doc, Node* node);
Node* dropEmbed(TidyDocImpl* doc, Node* node);
Node* dropCdata(TidyDocImpl* doc, Node* node);
Node* dropEmbedSrc(TidyDocImpl* doc, Node* node);
Node* dropJavascriptProps(TidyDocImpl* doc, Node* node);
Node* dropFileUrlProps(TidyDocImpl* doc, Node* node);
Node* dropHtmlEvents(TidyDocImpl* doc, Node* node);
Node* dropDataProperties(TidyDocImpl* doc, Node* node);

byte isContainsHtmlEvent(tmbstr string);

int TIDY_CALL ig_tidySanitize( TidyDoc tdoc )
{
    TidyDocImpl* impl = tidyDocToImpl( tdoc );
    if ( impl )
        return tidyDocSanitize( impl );
    return -EINVAL;
}

int tidyDocSanitize( TidyDocImpl* doc )
{
    dropScripts(doc, &doc->root);
    dropComments(doc, &doc->root);
    dropObject(doc, &doc->root);
    dropIframe(doc, &doc->root);
    //dropEmbed(doc, &doc->root);
    dropCdata(doc, &doc->root);
    dropEmbedSrc(doc, &doc->root);
    dropJavascriptProps(doc, &doc->root);
    dropFileUrlProps(doc, &doc->root);
    dropHtmlEvents(doc, &doc->root);
    dropDataProperties(doc, &doc->root);
    return 0;
}

Node* dropScripts(TidyDocImpl* doc, Node* node) {
    Node* next;
    
    while (node)
    {
        next = node->next;
        
        if (nodeIsSCRIPT(node))
        {
            TY_(RemoveNode)(node);
            TY_(FreeNode)(doc, node);
            node = next;
        } else {
            if (node->content)
                dropScripts(doc, node->content);
        }
        
        node = next;
    }
    return node;
}


Node* dropComments(TidyDocImpl* doc, Node* node) {
    Node* next;
    
    while (node)
    {
        next = node->next;
        
        if (node->type == CommentTag)
        {
            TY_(RemoveNode)(node);
            TY_(FreeNode)(doc, node);
            node = next;
        } else {
            if (node->content)
                dropComments(doc, node->content);
        }
        
        node = next;
    }
    return node;
}

Node* dropObject(TidyDocImpl* doc, Node* node) {
    Node* next;
    
    while (node)
    {
        next = node->next;
        
        if (nodeIsOBJECT(node))
        {
            TY_(RemoveNode)(node);
            TY_(FreeNode)(doc, node);
            node = next;
        } else {
            if (node->content)
                dropObject(doc, node->content);
        }
        
        node = next;
    }
    return node;
}

Node* dropIframe(TidyDocImpl* doc, Node* node) {
    Node* next;
    
    while (node)
    {
        next = node->next;
        
        if (nodeIsIFRAME(node))
        {
            TY_(RemoveNode)(node);
            TY_(FreeNode)(doc, node);
            node = next;
        } else {
            if (node->content)
                dropIframe(doc, node->content);
        }
        
        node = next;
    }
    return node;
}

Node* dropEmbed(TidyDocImpl* doc, Node* node) {
    Node* next;
    
    while (node)
    {
        next = node->next;
        
        if (nodeIsEMBED(node))
        {
            TY_(RemoveNode)(node);
            TY_(FreeNode)(doc, node);
            node = next;
        } else {
            if (node->content)
                dropEmbed(doc, node->content);
        }
        
        node = next;
    }
    return node;
}

Node* dropCdata(TidyDocImpl* doc, Node* node) {
    Node* next;
    
    while (node)
    {
        next = node->next;
        
        if (node->type == TidyNode_CDATA)
        {
            TY_(RemoveNode)(node);
            TY_(FreeNode)(doc, node);
            node = next;
        } else {
            if (node->content)
                dropCdata(doc, node->content);
        }
        
        node = next;
    }
    return node;
}

Node* dropEmbedSrc(TidyDocImpl* doc, Node* node) {
    Node* next;
    AttVal* attr;
    AttVal* attr_next;
    
    while (node)
    {
        next = node->next;
        
        if (nodeIsEMBED(node))
        {
            attr = node->attributes;
            while(attr) {
                attr_next = attr->next;
                
                // Strip all src properties
                if (TY_(tmbsubstr)(attr->attribute, "src")) {
                    TY_(RemoveAttribute)(doc, node, attr);
                }
                
                attr = attr_next;
            }
            
        } else {
            if (node->content)
                dropEmbedSrc(doc, node->content);
        }
        
        node = next;
    }
    return node;
}

Node* dropJavascriptProps(TidyDocImpl* doc, Node* node) {
    Node* next;
    AttVal* attr;
    AttVal* attr_next;
    
    while (node)
    {
        next = node->next;
        
        attr = node->attributes;
        while(attr) {
            attr_next = attr->next;
            
            if (TY_(tmbsubstr)(attr->value, "javascript:")) {
                TY_(RemoveAttribute)(doc, node, attr);
            }
            
            attr = attr_next;
        }
        
        if (node->content)
            dropJavascriptProps(doc, node->content);
        
        node = next;
    }
    return node;
}

Node* dropFileUrlProps(TidyDocImpl* doc, Node* node) {
    Node* next;
    AttVal* attr;
    AttVal* attr_next;
    
    while (node)
    {
        next = node->next;
        
        attr = node->attributes;
        while(attr) {
            attr_next = attr->next;
            
            if (TY_(tmbsubstr)(attr->value, "file:")) {
                TY_(RemoveAttribute)(doc, node, attr);
            }
            
            attr = attr_next;
        }
        
        if (node->content)
            dropFileUrlProps(doc, node->content);
        
        node = next;
    }
    return node;
}

Node* dropHtmlEvents(TidyDocImpl* doc, Node* node) {
    Node* next;
    AttVal* attr;
    AttVal* attr_next;
    
    while (node)
    {
        next = node->next;
        
        attr = node->attributes;
        while(attr) {
            attr_next = attr->next;
            
            if (isContainsHtmlEvent(attr->attribute) || isContainsHtmlEvent(attr->value)) {
                TY_(RemoveAttribute)(doc, node, attr);
            }
            
            attr = attr_next;
        }
        
        if (node->content)
            dropHtmlEvents(doc, node->content);
        
        node = next;
    }
    return node;
}

Node* dropDataProperties(TidyDocImpl* doc, Node* node) {
    Node* next;
    AttVal* attr;
    AttVal* attr_next;
    
    while (node)
    {
        next = node->next;
        
        attr = node->attributes;
        while(attr) {
            attr_next = attr->next;
            
            if (TY_(tmbsubstr)(attr->attribute, "src") ||
                TY_(tmbsubstr)(attr->attribute, "data")) {
                ctmbstr data = TY_(tmbsubstr)(attr->value, "data:");
                ctmbstr texthtml = TY_(tmbsubstr)(attr->value, "text/html");
                
                if (data || texthtml) {
                    TY_(RemoveAttribute)(doc, node, attr);
                }
            }
            
            attr = attr_next;
        }
        
        if (node->content)
            dropDataProperties(doc, node->content);
        
        node = next;
    }
    return node;
}

byte isContainsHtmlEvent(tmbstr string) {
    // By http://www.w3schools.com/tags/ref_eventattrubutes.asp
    return
        // Window events
        TY_(tmbsubstr)(string, "onafterprint") ||
        TY_(tmbsubstr)(string, "onbeforeprint") ||
        TY_(tmbsubstr)(string, "onbeforeunload") ||
        TY_(tmbsubstr)(string, "onerror") ||
        TY_(tmbsubstr)(string, "onhaschange") ||
        TY_(tmbsubstr)(string, "onload") ||
        TY_(tmbsubstr)(string, "onmessage") ||
        TY_(tmbsubstr)(string, "onoffline") ||
        TY_(tmbsubstr)(string, "ononline") ||
        TY_(tmbsubstr)(string, "onpagehide") ||
        TY_(tmbsubstr)(string, "onpageshow") ||
        TY_(tmbsubstr)(string, "onpopstate") ||
        TY_(tmbsubstr)(string, "onredo") ||
        TY_(tmbsubstr)(string, "onresize") ||
        TY_(tmbsubstr)(string, "onstorage") ||
        TY_(tmbsubstr)(string, "onundo") ||
        TY_(tmbsubstr)(string, "onunload") ||
        
        // Form Events
        TY_(tmbsubstr)(string, "onblur") ||
        TY_(tmbsubstr)(string, "onchange") ||
        TY_(tmbsubstr)(string, "oncontextmenu") ||
        TY_(tmbsubstr)(string, "onfocus") ||
        TY_(tmbsubstr)(string, "onformchange") ||
        TY_(tmbsubstr)(string, "onforminput") ||
        TY_(tmbsubstr)(string, "oninput") ||
        TY_(tmbsubstr)(string, "oninvalid") ||
        TY_(tmbsubstr)(string, "onreset") ||
        TY_(tmbsubstr)(string, "onselect") ||
        TY_(tmbsubstr)(string, "onsubmit") ||
        
        // Keyboard events
        TY_(tmbsubstr)(string, "onkeydown") ||
        TY_(tmbsubstr)(string, "onkeypress") ||
        TY_(tmbsubstr)(string, "onkeyup") ||
        
        // Mouse events
        TY_(tmbsubstr)(string, "onclick") ||
        TY_(tmbsubstr)(string, "ondblclick") ||
        TY_(tmbsubstr)(string, "ondrag") ||
        TY_(tmbsubstr)(string, "ondragend") ||
        TY_(tmbsubstr)(string, "ondragenter") ||
        TY_(tmbsubstr)(string, "ondragleave") ||
        TY_(tmbsubstr)(string, "ondragover") ||
        TY_(tmbsubstr)(string, "ondragstart") ||
        TY_(tmbsubstr)(string, "ondrop") ||
        TY_(tmbsubstr)(string, "onmousedown") ||
        TY_(tmbsubstr)(string, "onmousemove") ||
        TY_(tmbsubstr)(string, "onmouseout") ||
        TY_(tmbsubstr)(string, "onmouseover") ||
        TY_(tmbsubstr)(string, "onmouseup") ||
        TY_(tmbsubstr)(string, "onmousewheel") ||
        TY_(tmbsubstr)(string, "onscroll") ||
        
        // Media Events
        TY_(tmbsubstr)(string, "onabort") ||
        TY_(tmbsubstr)(string, "oncanplay") ||
        TY_(tmbsubstr)(string, "oncanplaythrough") ||
        TY_(tmbsubstr)(string, "ondurationchange") ||
        TY_(tmbsubstr)(string, "onemptied") ||
        TY_(tmbsubstr)(string, "onended") ||
        TY_(tmbsubstr)(string, "onerror") ||
        TY_(tmbsubstr)(string, "onloadeddata") ||
        TY_(tmbsubstr)(string, "onloadedmetadata") ||
        TY_(tmbsubstr)(string, "onloadstart") ||
        TY_(tmbsubstr)(string, "onpause") ||
        TY_(tmbsubstr)(string, "onplay") ||
        TY_(tmbsubstr)(string, "onplaying") ||
        TY_(tmbsubstr)(string, "onprogress") ||
        TY_(tmbsubstr)(string, "onratechange") ||
        TY_(tmbsubstr)(string, "onreadystatechange") ||
        TY_(tmbsubstr)(string, "onseeked") ||
        TY_(tmbsubstr)(string, "onseeking") ||
        TY_(tmbsubstr)(string, "onstalled") ||
        TY_(tmbsubstr)(string, "onsuspend") ||
        TY_(tmbsubstr)(string, "ontimeupdate") ||
        TY_(tmbsubstr)(string, "onvolumechange") ||
        TY_(tmbsubstr)(string, "onwaiting") ||
    
        // 2013-08-23 : Prevent all on* events
        ((TY_(tmbstrlen)(string) >= 2) && (string[0]=='o' || string[0]=='O') && (string[1]=='n' || string[1]=='N'));
}
