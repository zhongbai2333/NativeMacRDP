#import "input/ClipboardSync.h"
#import <AppKit/AppKit.h>
#define RDP_LOG_COMPONENT "clipboard"
#include "logging/RDPLog.h"

/*
 * macOS provides NO pasteboard-change notification (NSPasteboard has no KVO and
 * no NSNotification for content changes — the previously-used
 * "com.apple.pasteboard.application-active" distributed note does not fire on
 * copy). The only reliable way to detect a copy is to poll NSPasteboard.changeCount.
 * We poll a few times a second; when idle this is just an integer comparison.
 */

@interface ClipboardSync ()
@property (nonatomic, assign) NSInteger lastChangeCount;
@property (nonatomic, strong) dispatch_source_t pollTimer;
@end

@implementation ClipboardSync

- (void)start {
    _lastChangeCount = NSPasteboard.generalPasteboard.changeCount;

    _pollTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                    dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(_pollTimer, dispatch_time(DISPATCH_TIME_NOW, 0),
                              (uint64_t)(NSEC_PER_SEC / 4), NSEC_PER_SEC / 8); /* ~4 Hz */
    __weak typeof(self) weak = self;
    dispatch_source_set_event_handler(_pollTimer, ^{ [weak pollPasteboard]; });
    dispatch_resume(_pollTimer);

    rdp_verbose("clipboard sync started (polling changeCount ~4Hz)");
}

- (void)stop {
    if (_pollTimer) { dispatch_source_cancel(_pollTimer); _pollTimer = nil; }
    rdp_verbose("clipboard sync stopped");
}

/* Mac -> Windows: when the pasteboard changes, advertise the new contents. */
- (void)pollPasteboard {
    NSPasteboard *pb = NSPasteboard.generalPasteboard;
    NSInteger cc = pb.changeCount;
    if (cc == _lastChangeCount) return;
    _lastChangeCount = cc;

    ClipboardSendBlock block = self.sendToClientBlock;
    ClipboardSendFilesBlock filesBlock = self.sendFilesToClientBlock;
    if (!block && !filesBlock) return;

    /* Finder places file URLs on the pasteboard alongside string-compatible
     * representations of their paths. Detect files before text, otherwise
     * stringForType: turns a copied file into plain path text and CLIPRDR never
     * gets the stream-backed FileGroupDescriptorW format it needs. */
    if (filesBlock) {
        NSDictionary *options = @{
            NSPasteboardURLReadingFileURLsOnlyKey: @YES
        };
        NSArray<NSURL *> *urls = [pb readObjectsForClasses:@[ NSURL.class ]
                                                   options:options];
        NSMutableArray<NSString *> *paths =
            [NSMutableArray arrayWithCapacity:urls.count];
        for (NSURL *url in urls) {
            if (url.isFileURL && url.path.length > 0)
                [paths addObject:url.path];
        }

        /* Finder and some older Cocoa applications still publish the legacy
         * filename-list representation without a readable public.file-url. */
        if (paths.count == 0) {
            id legacy = [pb propertyListForType:@"NSFilenamesPboardType"];
            if ([legacy isKindOfClass:NSArray.class]) {
                for (id value in (NSArray *)legacy) {
                    if ([value isKindOfClass:NSString.class] &&
                        [(NSString *)value length] > 0)
                        [paths addObject:value];
                }
            }
        }

        if (paths.count > 0) {
            rdp_info("Mac clipboard changed: detected %zu file(s)",
                     (size_t)paths.count);
            filesBlock(paths);
            return;
        }
    }

    NSString *str = [pb stringForType:NSPasteboardTypeString];
    if (str && block) {
        NSData *utf16 = [str dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
        if (utf16) {
            /* MS-RDPECLIP: CF_UNICODETEXT data is expected to be NUL-terminated.
             * NSString's encoding does not append one, so add a trailing U+0000.
             * Unicode/emoji are preserved (surrogate pairs are just more code
             * units); large blocks are sent in full (no truncation). */
            NSMutableData *out = [utf16 mutableCopy];
            const uint16_t nul = 0;
            [out appendBytes:&nul length:sizeof(nul)];
            rdp_verbose("clipboard: Mac copy -> %zu UTF-16 bytes to client",
                        (size_t)out.length);
            block((const uint8_t *)out.bytes, out.length, RDP_CB_FORMAT_UNICODETEXT);
        }
        return;
    }
    NSData *png = [pb dataForType:NSPasteboardTypePNG];
    if (png && block) {
        rdp_verbose("clipboard: Mac copy -> %zu PNG bytes to client", (size_t)png.length);
        block((const uint8_t *)png.bytes, png.length, RDP_CB_FORMAT_PNG);
    }
}

/* Windows -> Mac: client sent clipboard data; place it on the Mac pasteboard. */
- (void)receiveFromClient:(const uint8_t *)data length:(size_t)len format:(uint32_t)format {
    NSPasteboard *pb = NSPasteboard.generalPasteboard;
    [pb clearContents];
    if (format == RDP_CB_FORMAT_UNICODETEXT || format == RDP_CB_FORMAT_TEXT) {
        NSString *str = nil;
        if (format == RDP_CB_FORMAT_TEXT) {
            /* CF_TEXT is ANSI/codepage bytes, NUL-terminated. */
            str = [[NSString alloc] initWithData:[NSData dataWithBytes:data length:len]
                                        encoding:NSWindowsCP1252StringEncoding];
        } else {
            /* CF_UNICODETEXT is UTF-16LE and mstsc terminates it with a U+0000.
             * Decoding the trailing NUL yields a stray \0 the Mac pasteboard keeps
             * verbatim, so trim a single trailing UTF-16 NUL (2 bytes) if present.
             * Full length is honoured otherwise — no truncation of large blocks. */
            size_t blen = len;
            if (blen >= 2 && data[blen - 1] == 0 && data[blen - 2] == 0)
                blen -= 2;
            str = [[NSString alloc] initWithData:[NSData dataWithBytes:data length:blen]
                                        encoding:NSUTF16LittleEndianStringEncoding];
        }
        if (str) {
            [pb setString:str forType:NSPasteboardTypeString];
            _lastChangeCount = pb.changeCount;  /* don't bounce it back to the client */
            rdp_verbose("clipboard: received %zu bytes from client (text)", len);
        } else {
            rdp_verbose("clipboard: failed to decode %zu text bytes from client", len);
        }
    } else if (format == RDP_CB_FORMAT_PNG) {
        [pb setData:[NSData dataWithBytes:data length:len] forType:NSPasteboardTypePNG];
        _lastChangeCount = pb.changeCount;
        rdp_verbose("clipboard: received %zu bytes from client (PNG)", len);
    }
}

- (BOOL)receiveFilesFromClientPaths:(const char *const *)paths
                              count:(size_t)count {
    if (!paths || count == 0) return NO;

    NSMutableArray<NSURL *> *urls =
        [NSMutableArray arrayWithCapacity:count];
    for (size_t i = 0; i < count; i++) {
        if (!paths[i] || !paths[i][0]) return NO;
        NSString *path = [NSString stringWithUTF8String:paths[i]];
        if (!path) return NO;
        [urls addObject:[NSURL fileURLWithPath:path isDirectory:NO]];
    }

    NSPasteboard *pb = NSPasteboard.generalPasteboard;
    [pb clearContents];
    if (![pb writeObjects:urls]) {
        rdp_error("clipboard: failed to publish %zu downloaded file(s)", count);
        return NO;
    }
    _lastChangeCount = pb.changeCount;  /* do not advertise the staged files back */
    rdp_info("Windows clipboard ready: published %zu file(s) to Finder", count);
    return YES;
}

@end
