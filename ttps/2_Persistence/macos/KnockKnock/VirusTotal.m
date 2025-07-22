//
//  VirusTotal.m
//  KnockKnock
//
//  Created by Patrick Wardle on 3/8/15.
//  Copyright (c) 2015 Objective-See. All rights reserved.
//

#import "File.h"
#import "ItemBase.h"
#import "Utilities.h"
#import "PluginBase.h"
#import "VirusTotal.h"
#import "AppDelegate.h"

/* GLOBALS */

//cmdline flag
extern BOOL cmdlineMode;

@implementation VirusTotal

//thread function
// runs in the background to get virus total info about a plugin's items
-(void)getInfo:(PluginBase*)plugin
{
    //plugin file items
    // in dictionary w/ SHA1 hash as key
    NSMutableDictionary* uniqueItems = nil;
    
    //File object
    File* item = nil;
    
    //item data
    NSMutableDictionary* itemData = nil;
    
    //items
    NSMutableArray* items = nil;
    
    //VT query URL
    NSURL* queryURL = nil;
    
    //results
    NSDictionary* results = nil;
    
    //alloc dictionary for plugin file items
    uniqueItems = [NSMutableDictionary dictionary];
    
    //alloc list for items
    items = [NSMutableArray array];
    
    //init query URL
    queryURL = [NSURL URLWithString:[NSString stringWithFormat:@"%@%@", VT_QUERY_URL, VT_API_KEY]];
    
    //sync
    // ->since array will be reset if user clicks 'stop' scan
    @synchronized(plugin.allItems)
    {
    
    //place all plugin file items into dictionary
    // ->key: hash, filter's out dups for queries
    for(ItemBase* item in plugin.allItems)
    {
        //skip non-file items
        if(YES != [item isKindOfClass:[File class]])
        {
            //skip
            continue;
        }
        
        //skip item's without hashes
        // ...not sure how this could ever happen
        if(nil == ((File*)item).hashes[KEY_HASH_SHA1])
        {
            //skip
            continue;
        }
        
        //add item
        uniqueItems[((File*)item).hashes[KEY_HASH_SHA1]] = item;
    }
        
    }//sync
    
    //iterate over all hashes
    // ->create item dictionary (JSON), and add it to list
    for(NSString* itemKey in uniqueItems)
    {
        //sanitized path
        NSString* sanitizedPath = nil;
        
        //current user
        NSString* currentUser = nil;
        
        //alloc item data
        itemData = [NSMutableDictionary dictionary];
        
        //exit if thread was cancelled
        // ->i.e. user pressed 'stop' scan
        if(YES == [[NSThread currentThread] isCancelled])
        {
            //exit
            [NSThread exit];
        }
        
        //get current user
        currentUser = getConsoleUser();
        
        //sanitize path
        sanitizedPath = [item.path stringByReplacingOccurrencesOfString:currentUser withString:@"user"];
        
        //extract item
        item = uniqueItems[itemKey];
        
        //auto start location
        itemData[@"autostart_location"] = plugin.name;
        
        //set item name
        itemData[@"autostart_entry"] = item.name;
        
        //set item path
        itemData[@"image_path"] = sanitizedPath;
        
        //set hash
        itemData[@"hash"] = item.hashes[KEY_HASH_SHA1];
        
        //set creation times
        itemData[@"creation_datetime"] = [item.attributes.fileCreationDate description];
        
        //add item info to list
        [items addObject:itemData];
        
        //less then 25 items
        // ->just keep collecting items
        if(VT_MAX_QUERY_COUNT != items.count)
        {
            //next
            continue;
        }
        
        //make query to VT
        results = [self postRequest:queryURL parameters:items];
        if(200 == (long)[(NSHTTPURLResponse *)results[VT_HTTP_RESPONSE] statusCode])
        {
            //process results
            [self processResults:plugin.allItems results:results];
        }
        
        //remove all items
        // since they've been processed
        [items removeAllObjects];
    }
    
    //process any remaining items
    if(0 != items.count)
    {
        //query virus total
        results = [self postRequest:queryURL parameters:items];
        if(200 == (long)[(NSHTTPURLResponse *)results[VT_HTTP_RESPONSE] statusCode])
        {
            //process results
            [self processResults:plugin.allItems results:results];
        }
    }
    
    //exit if thread was cancelled
    // ->i.e. user pressed 'stop' scan
    if(YES == [[NSThread currentThread] isCancelled])
    {
        //exit
        [NSThread exit];
    }
    
    //tell UI all plugin's items have all be processed
    if(YES != cmdlineMode)
    {
        //on main thread
        dispatch_async(dispatch_get_main_queue(), ^{
            
            //call up into UI
            [((AppDelegate*)[[NSApplication sharedApplication] delegate]) itemsProcessed:plugin];
            
        });
        
    }

    return;
}

//item data
//(NSMutableDictionary*)covertItemToRequest:(Item*)


//get VT info for a single item
// will then callback into AppDelegate to reload item in UI
-(BOOL)getInfoForItem:(File*)fileObj scanID:(NSString*)scanID
{
    //result
    BOOL gotInfo = NO;
    
    //VT query URL
    NSURL* queryURL = nil;
    
    //results
    NSDictionary* results = nil;
    
    //alert
    __block NSAlert* alert = nil;
    
    //init query URL
    queryURL = [NSURL URLWithString:[NSString stringWithFormat:@"%@?apikey=%@&resource=%@", VT_REQUERY_URL, VT_API_KEY, scanID]];
    
    //make queries until response is recieved
    while(YES)
    {
        //make query to VT
        results = [self postRequest:queryURL parameters:nil];
        if(200 != (long)[(NSHTTPURLResponse *)results[VT_HTTP_RESPONSE] statusCode])
        {
            //update status msg
            dispatch_async(dispatch_get_main_queue(), ^{
                
                //alloc/init alert
                alert = [NSAlert alertWithMessageText:[NSString stringWithFormat:NSLocalizedString(@"ERROR:\nVirusTotal query for '%@' failed", @"ERROR:\nVirusTotal query for '%@' failed"), fileObj.name] defaultButton:NSLocalizedString(@"OK", @"OK") alternateButton:nil otherButton:nil informativeTextWithFormat:NSLocalizedString(@"HTTP reponse: %ld", @"HTTP reponse: %ld"), (long)[(NSHTTPURLResponse *)results[VT_HTTP_RESPONSE] statusCode]];
                
                //show it
                [alert runModal];
                
            });
            
            break;
        }

        //check if scan is complete
        if( (nil != results) &&
            (1 == [results[VT_RESULTS_RESPONSE] integerValue]) )
        {
            //save result
            fileObj.vtInfo = results;
            
            //if its flagged save in File's plugin
            if(0 != [results[VT_RESULTS_POSITIVES] unsignedIntegerValue])
            {
                //sync
                // ->since array will be reset if user clicks 'stop' scan
                @synchronized(fileObj.plugin.flaggedItems)
                {
                    //save
                    [fileObj.plugin.flaggedItems addObject:fileObj];
                }
            }
            //if its unknown save
            if(nil == results[VT_RESULTS_URL])
            {
                //sync
                // since array will be reset if user clicks 'stop' scan
                @synchronized(fileObj.plugin.unknownItems)
                {
                    //save
                    [fileObj.plugin.unknownItems addObject:fileObj];
                }
            }
            
            //update status msg
            dispatch_async(dispatch_get_main_queue(), ^{
                
                //callback up into UI to reload item
                [((AppDelegate*)[[NSApplication sharedApplication] delegate]) itemProcessed:fileObj];
                
            });
            
            //happy
            gotInfo = YES;

            //exit loop
            break;
        }
        
        //nap
        [NSThread sleepForTimeInterval:10.0f];
    }
    
    return gotInfo;
}

//make the (POST)query to VT
-(NSDictionary*)postRequest:(NSURL*)url parameters:(id)params
{
    //results
    NSMutableDictionary* results = nil;
    
    //request
    NSMutableURLRequest* request = nil;
    
    //http response
    NSURLResponse* httpResponse = nil;
    
    //post data
    // ->JSON'd items
    NSData* postData = nil;
    
    //error var
    NSError* error = nil;
    
    //data from VT
    NSData* vtData = nil;

    //alloc/init request
    request = [[NSMutableURLRequest alloc] initWithURL:url];
    
    //init
    results = [NSMutableDictionary dictionary];
    
    //set user agent
    [request setValue:VT_USER_AGENT forHTTPHeaderField:@"User-Agent"];

    //serialize JSON
    if(nil != params)
    {
        //convert items to JSON'd data for POST request
        @try
        {
            //convert items
            postData = [NSJSONSerialization dataWithJSONObject:params options:kNilOptions error:nil];
            if(nil == postData)
            {
                //err msg
                NSLog(@"ERROR: failed to convert request %@ to JSON", postData);
                goto bail;
            }
            
        }
        //bail on exceptions
        @catch(NSException *exception)
        {
            //set error
            goto bail;
        }
        
        //set content type
        [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        
        //set content length
        [request setValue:[NSString stringWithFormat:@"%lu", (unsigned long)[postData length]] forHTTPHeaderField:@"Content-length"];
        
        //add POST data
        [request setHTTPBody:postData];
    }
    
    //set method type
    [request setHTTPMethod:@"POST"];
    
    //send request
    // synchronous, so will block
    vtData = [NSURLConnection sendSynchronousRequest:request returningResponse:&httpResponse error:&error];
    
    //save http response
    results[VT_HTTP_RESPONSE] = httpResponse;
    
    //sanity check(s)
    if( (nil == vtData) ||
        (nil != error) ||
        (200 != (long)[(NSHTTPURLResponse *)httpResponse statusCode]) )
    {
        //err msg
        NSLog(@"ERROR: failed to query VirusTotal (%@, %@)", error, httpResponse);
        goto bail;
    }
    
    //serialize response into NSData obj
    // wrap since we are serializing JSON
    @try
    {
        //serialized
        results = [[NSJSONSerialization JSONObjectWithData:vtData options:kNilOptions error:nil] mutableCopy];
        if(YES != [results isKindOfClass:[NSDictionary class]])
        {
            //bail
            goto bail;
        }
        
        //(re)add http response
        results[VT_HTTP_RESPONSE] = httpResponse;
    }
    //bail on any exceptions
    @catch (NSException *exception)
    {
        //err msg
        NSLog(@"ERROR: converting response %@ to JSON threw %@", vtData, exception);
        goto bail;
    }
    
    //sanity check
    if(nil == results)
    {
        //err msg
        NSLog(@"ERROR: failed to convert response %@ to JSON", vtData);
        goto bail;
    }
    
//bail
bail:
    
    return results;
}

//submit a file to VT
-(NSDictionary*)submit:(File*)fileObj
{
    //results
    NSMutableDictionary* results = nil;
    
    //submit URL
    NSURL* submitURL = nil;
    
    //request
    NSMutableURLRequest* request = nil;
    
    //body of request
    NSMutableData* body = nil;
    
    //file data
    NSData* fileContents = nil;
    
    //error var
    NSError* error = nil;
    
    //data from Vt
    NSData* vtData = nil;
    
    //response (HTTP) from VT
    NSURLResponse* httpResponse = nil;
    
    //init
    results = [NSMutableDictionary dictionary];

    //init submit URL
    submitURL = [NSURL URLWithString:[NSString stringWithFormat:@"%@?apikey=%@&resource=%@", VT_SUBMIT_URL, VT_API_KEY, fileObj.hashes[KEY_HASH_MD5]]];
    
    //init request
    request = [[NSMutableURLRequest alloc] initWithURL:submitURL];
    
    //set boundary string
    NSString *boundary = @"qqqq___knockknock___qqqq";
    
    //set HTTP method (POST)
    [request setHTTPMethod:@"POST"];
    
    //set the HTTP header 'Content-type' to the boundary
    [request setValue:[NSString stringWithFormat:@"multipart/form-data; boundary=%@", boundary] forHTTPHeaderField: @"Content-Type"];
    
    //set HTTP header, 'User-Agent'
    [request setValue:VT_USER_AGENT forHTTPHeaderField:@"User-Agent"];

    //init body
    body = [NSMutableData data];
    
    //load file into memory
    fileContents = [NSData dataWithContentsOfFile:fileObj.pathForFinder];
    
    //sanity check
    if(nil == fileContents)
    {
        //err msg
        NSLog(@"ERROR: failed to load %@ into memory for submission", fileObj.path);
        goto bail;
    }
        
    //append boundary
    [body appendData:[[NSString stringWithFormat:@"--%@\r\n", boundary] dataUsingEncoding:NSUTF8StringEncoding]];
    
    //append 'Content-Disposition' file name, etc
    [body appendData:[[NSString stringWithFormat:@"Content-Disposition: form-data; name=\"file\"; filename=\"%@\"\r\n", fileObj.name] dataUsingEncoding:NSUTF8StringEncoding]];
    
    //append 'Content-Type'
    [body appendData:[@"Content-Type: application/octet-stream\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding]];
    
    //append file's contents
    [body appendData:fileContents];
    
    //append '\r\n'
    [body appendData:[[NSString stringWithFormat:@"\r\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    
    //append final boundary
    [body appendData:[[NSString stringWithFormat:@"--%@--\r\n", boundary] dataUsingEncoding:NSUTF8StringEncoding]];
    
    //set body
    [request setHTTPBody:body];
    
    //set content length
    [request setValue:[NSString stringWithFormat:@"%lu", (unsigned long)[body length]] forHTTPHeaderField:@"Content-length"];

    //send request
    // synchronous, so will block
    vtData = [NSURLConnection sendSynchronousRequest:request returningResponse:&httpResponse error:&error];
    
    //save http response
    results[VT_HTTP_RESPONSE] = httpResponse;
    
    //sanity check(s)
    if( (nil == vtData) ||
        (nil != error) ||
        (200 != (long)[(NSHTTPURLResponse *)httpResponse statusCode]) )
    {
        //err msg
        NSLog(@"ERROR: failed to query VirusTotal (%@, %@)", error, httpResponse);
        goto bail;
    }
    
    //serialize response into NSData obj
    // ->wrap since we are serializing JSON
    @try
    {
        //serialize
        results = [[NSJSONSerialization JSONObjectWithData:vtData options:kNilOptions error:nil] mutableCopy];
        if(YES != [results isKindOfClass:[NSDictionary class]])
        {
            //bail
            goto bail;
        }
        
        //(re)add http response
        results[VT_HTTP_RESPONSE] = httpResponse;
    }
    //bail on any exceptions
    @catch (NSException *exception)
    {
        //err msg
        NSLog(@"ERROR: converting response %@ to JSON threw %@", vtData, exception);
        goto bail;
    }
    
    //sanity check
    if(nil == results)
    {
        //err msg
        NSLog(@"ERROR: failed to convert response %@ to JSON", vtData);
        goto bail;
    }
    
bail:
    
    return results;
}

//submit a rescan request
-(NSDictionary*)reScan:(File*)fileObj
{
    //result data
    NSDictionary* results = nil;
    
    //scan url
    NSURL* reScanURL = nil;
    
    //http response
    NSURLResponse* httpResponse = nil;
    
    //init scan url
    reScanURL = [NSURL URLWithString:[NSString stringWithFormat:@"%@?apikey=%@&resource=%@", VT_RESCAN_URL, VT_API_KEY, fileObj.hashes[KEY_HASH_MD5]]];
    
    //make request to VT
    results = [self postRequest:reScanURL parameters:nil];
    if(200 != (long)[(NSHTTPURLResponse *)httpResponse statusCode])
    {
        //err msg
        NSLog(@"ERROR: failed to re-scan %@", fileObj.name);
        goto bail;
    }

bail:
    
    return results;
}

//process results
// save VT info into each File obj and all flagged files
-(void)processResults:(NSArray*)items results:(NSDictionary*)results
{
    //process all results
    // save VT result dictionary into File obj
    for(NSDictionary* result in results[VT_RESULTS])
    {
        //sync
        // ->since array will be reset if user clicks 'stop' scan
        @synchronized(items)
        {

        //find all items that match
        // ->might be dupes, which is fine
        for(ItemBase* item in items)
        {
            //skip non-file items
            if(YES != [item isKindOfClass:[File class]])
            {
                //skip
                continue;
            }
            
            //for matches, save vt info
            if(YES == [result[@"hash"] isEqualToString:((File*)item).hashes[KEY_HASH_SHA1]])
            {
                //save
                ((File*)item).vtInfo = result;
                
                //if its flagged save in File's plugin
                if(0 != [result[VT_RESULTS_POSITIVES] unsignedIntegerValue])
                {
                    //sync
                    // ->since array will be reset if user clicks 'stop' scan
                    @synchronized(item.plugin.flaggedItems)
                    {
                        //save
                        [item.plugin.flaggedItems addObject:item];
                    }
                }
                //if its unknown save
                if(nil == result[VT_RESULTS_URL])
                {
                    //sync
                    // ->since array will be reset if user clicks 'stop' scan
                    @synchronized(item.plugin.unknownItems)
                    {
                        //save
                        [item.plugin.unknownItems addObject:item];
                    }
                }
            }
        }
            
        }//sync
    }
    
    return;
}

@end
