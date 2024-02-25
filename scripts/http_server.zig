const std = @import("std");
const Server = @import("std").http.Server;

const DEFAULT_BIND_ADDRESS : [4]u8 = [4]u8 {127, 0, 0, 1};
const DEFAULT_BIND_PORT: u16 = 3000;
const FILE_BUFFER_SIZE: usize = 1024;
const FetchError = std.fs.File.OpenError || std.mem.Allocator.Error || std.os.PipeError || std.os.AccessError || std.os.ReadError || std.http.Server.Response.WriteError;

const Hyperlink = struct {
    href:  []const u8,
    label: []const u8,
};

const Allocator = std.mem.Allocator;

const Hyperlinks = struct {
    const Self = @This();

    dir: std.fs.IterableDir,
    dir_iter: std.fs.IterableDir.Iterator,
    alloc: Allocator,
    current_hyperlink: Hyperlink,
    buffer: [std.fs.MAX_PATH_BYTES*2]u8,
    relative_path: []const u8,

    fn init(relative_path: []const u8, dir: std.fs.IterableDir) FetchError!Self {
        var buffer: [std.fs.MAX_PATH_BYTES*2]u8 = undefined;
        @memset(buffer[0..], 0);
        var fb = std.heap.FixedBufferAllocator.init(&buffer);
        const alloc = fb.allocator();
        var ch = Hyperlink {
            .href = try alloc.alloc(u8, std.fs.MAX_PATH_BYTES),
            .label = try alloc.alloc(u8, std.fs.MAX_PATH_BYTES),
        };
        var self = Self {
            .alloc = alloc,
            .buffer = buffer,
            .relative_path = relative_path,
            .dir = dir,
            .dir_iter = dir.iterate(),
            .current_hyperlink = ch,
        };

        return self;
    }

    fn next(self: *Self) !?Hyperlink {
        self.alloc.free(self.current_hyperlink.href);
        self.alloc.free(self.current_hyperlink.label);
        @memset(self.buffer[0..], 0);

        if(try self.dir_iter.next()) |entry| {
            const label = try std.fs.path.joinZ(self.alloc, &[_][]const u8 { entry.name });
            const href = try std.fs.path.joinZ(self.alloc, &[_][]const u8 { self.relative_path, entry.name });
            return Hyperlink { .href = href, .label = label };
        }

        return null;
    }

    fn deinit(self: Self) void {
        // In case we partially iterate
        self.alloc.free(self.current_hyperlink.href);
        self.alloc.free(self.current_hyperlink.label);
    }
};

pub fn list_dir(rsrc: *const Resource) FetchError!Hyperlinks {

    if(rsrc.handle != ResourceHandle.directory) {
        return error.NotDir;
    }

    const relative_path = rsrc.relative_path;
    const dir_path = rsrc.absolute_path;

    std.debug.print("dir_path: {s}\n", .{dir_path});
    var dir = rsrc.handle.directory;

    return Hyperlinks.init(relative_path, dir);
}

pub fn html_list_dir(writer: std.http.Server.Response.Writer, rsrc: *const Resource) FetchError!void {

    std.debug.print("Listing a directory: {s}", .{rsrc.relative_path});

    // const base_path = rsrc.base_path;
    // const relative_path = rsrc.relative_path;

    var hyperlinks = try list_dir(rsrc);
    defer hyperlinks.deinit();

    const anchors_first_part = "<a class=\"file-anchor\" href=\"";
    const anchors_second_part = "\"> ";
    const anchors_third_part = " </a><br/>";

    var hl = try list_dir(rsrc);
    defer hl.deinit();

    while(try hl.next()) |link| {
        try writer.writeAll(anchors_first_part);
        try writer.writeAll(link.href);
        try writer.writeAll(anchors_second_part);
        try writer.writeAll(link.label);
        try writer.writeAll(anchors_third_part);
    }
}

const ResourceType = enum {
    file, directory, static_html,
};

const ResourceHandle = union(ResourceType) {
    file: std.fs.File,
    directory: std.fs.IterableDir,
    static_html: []const u8,
};

const Resource = struct {
    const Self = @This();

    handle: ResourceHandle,
    content_type: []const u8,
    base_path: []const u8,
    relative_path: []const u8,
    absolute_path: []const u8,
    path_buffer: [std.fs.MAX_PATH_BYTES]u8,
    alloc: std.mem.Allocator,
    resource_size: ?usize,

    fn locate(base_path: []const u8, relative_path: []const u8) !Self {
        var path_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        @memset(path_buffer[0..], 0);
        var fb = std.heap.FixedBufferAllocator.init(&path_buffer);
        const alloc = fb.allocator();
        var absolute_path = try std.fs.path.join(alloc, &[_][]const u8{base_path, relative_path});
        var content_type: []const u8 = "application/octet-stream";
        var rh = ResourceHandle{ .static_html = "<h1>Something went wrong!</h1>" };

        var resource_size : ?usize = null;
        var file = try std.fs.openFileAbsolute(absolute_path, .{.mode = .read_only});
        const metadata = try file.metadata();

        switch (metadata.kind()) {
            .file => {
                if(std.mem.endsWith(u8, relative_path, ".html")) {
                    content_type = "text/html";
                }
                else if(std.mem.endsWith(u8, relative_path, ".js")) {
                    content_type = "text/javascript";
                }
                else if(std.mem.endsWith(u8, relative_path, ".wasm")) {
                    content_type = "application/wasm";
                }
                else if(std.mem.endsWith(u8, relative_path, ".css")) {
                    content_type = "text/css";
                }
                else if(std.mem.endsWith(u8, relative_path, ".png")) {
                    content_type = "image/png";
                }
                else if(std.mem.endsWith(u8, relative_path, ".svg")) {
                    content_type = "image/svg+xml";
                }
                else if(std.mem.endsWith(u8, relative_path, ".jpg") or std.mem.endsWith(u8, relative_path, ".jpeg") ) {
                    content_type = "image/jpeg";
                }

                std.debug.print("content_type: {s}\n", .{content_type});

                if(std.fs.openFileAbsolute(absolute_path, .{.mode = .read_only})) |f| {
                    std.debug.print("file resource: {s}\n", .{absolute_path});
                    resource_size = metadata.size();
                    std.debug.print("content-length: {?}\n", .{resource_size});
                    rh = ResourceHandle { .file = f };
                } else |err| {
                    std.debug.print("File not found ({s}): {}!\n", .{ absolute_path, err });
                    return error.AccessDenied;
                }
            },
            .directory => {
                alloc.free(absolute_path);
                file.close();
                absolute_path = try std.fs.path.join(alloc, &[_][]const u8 {base_path, relative_path, "index.html"});
                if(std.fs.openFileAbsolute(absolute_path, .{.mode = .read_only})) |index_file| {
                    rh = ResourceHandle { .file = index_file };
                    content_type = "text/html";

                } else |err| {
                    std.debug.print("Couldn't find index file, reverting a directory listing: {}!\n", .{ err });
                    alloc.free(absolute_path);
                    absolute_path = try std.fs.path.join(alloc, &[_][]const u8{base_path, relative_path});
                    var dir = try std.fs.openIterableDirAbsolute(absolute_path, .{.access_sub_paths = false});
                    content_type = "text/html";
                    rh = ResourceHandle{.directory = dir};
                }
            },
            else => {
                std.debug.print("Not a traditional file or directory: {s}\n", .{ absolute_path });
                content_type = "text/html";
                rh = ResourceHandle{ .static_html = "<h1> ERROR: Restricted resource: 'Not a traditional file or directory'" };
            }
        }

        std.debug.print("Located: {s}\n", .{absolute_path});
        return Self {
            .base_path = base_path,
            .relative_path = relative_path,
            .absolute_path = absolute_path,
            .path_buffer = path_buffer,
            .alloc = alloc,
            .content_type = content_type,
            .resource_size = resource_size,
            .handle = rh,
        };
    }

    pub fn send(self: *const Self, writer: std.http.Server.Response.Writer) FetchError!void {
        switch (self.handle)  {
            .file => |f| {
                var file_buffer: [FILE_BUFFER_SIZE]u8 = undefined;
                @memset(file_buffer[0..], 0);

                var bytes_read: usize = 0;
                var bytes_writen: usize = 0;
                var total_bytes_writen: usize = 0;

                // Read file from file system and write to response.
                while(true) {
                    bytes_read += try f.read(&file_buffer);
                    while (true) {
                        bytes_writen += writer.write(file_buffer[bytes_writen..bytes_read]) catch |err| {
                            std.debug.print("Failed writing to socket during file tranfer!\nError: {}", .{err});
                            return err;
                        };
                        if(bytes_writen >= bytes_read) {
                            break;
                        }
                    }
                    total_bytes_writen += bytes_writen;
                    if(bytes_read < file_buffer.len) {
                        break;
                    }
                    bytes_read = 0;
                    bytes_writen = 0;
                }

                std.debug.print("Total bytes writen: {}\n", .{total_bytes_writen});
            },
            .directory => |_| {
                try html_list_dir(writer, self);
            },
            .static_html => |static_html| {
                try writer.writeAll(static_html);
            },
            // else => {
            //     const static_html = "<h1 class=\"error-message\"> ERROR: Not a traditional file or a directory! </h1>";
            //     try writer.writeAll(static_html);
            // }
        }
    }

    fn deinit(self: *Self) !void {
        // Just in case we start using different allocator.
        self.alloc.free(self.path_buffer);
    }
};


const Config = struct {
    bind_addr: std.net.Address,
};

fn parse_args() Config {
    var args = std.process.args();

    // Executable name
    _ = args.next();

    var addr = std.net.Address {
        .in = std.net.Ip4Address.init(
            DEFAULT_BIND_ADDRESS,
            DEFAULT_BIND_PORT
        )
    };

    while(args.next()) |arg| {

        if(std.mem.eql(u8, arg, "--bind")) {

            if (args.next()) |ip_str| {
                addr = std.net.Address.resolveIp(ip_str, DEFAULT_BIND_PORT) catch default_ip: {
                    std.debug.print("Invalid ip address, using default binding {s}:{}\n", .{DEFAULT_BIND_ADDRESS, DEFAULT_BIND_PORT});
                    break :default_ip std.net.Address {
                        .in = std.net.Ip4Address.init(
                            DEFAULT_BIND_ADDRESS,
                            DEFAULT_BIND_PORT
                        )
                    };
                };

                var port: u16 = DEFAULT_BIND_PORT;

                if (args.next()) |port_str| {
                    port = std.fmt.parseInt(u16, port_str, 10) catch default_port: {
                        std.debug.print("Could not parse port number using default binding: {s}:{}", .{DEFAULT_BIND_ADDRESS, DEFAULT_BIND_PORT});
                        break :default_port DEFAULT_BIND_PORT;
                    };

                    addr.setPort(port);
                }
            }
        }
    }

    return Config {
        .bind_addr = addr
    };
}

pub fn main() !void {

    var gpa = std.heap.GeneralPurposeAllocator(.{}) {};
    const alloc = gpa.allocator();

    var config = parse_args();
    const bind_addr = config.bind_addr;

    defer {
        const status = gpa.deinit();
        if (status == .leak) {
            std.debug.print("Failed to deinit General Purpose allocator!", .{});
        }
    }

    var server = Server.init(alloc, .{ .reuse_address = true});
    defer server.deinit();

    try server.listen(bind_addr);

    var cwd : [std.fs.MAX_PATH_BYTES]u8 = undefined;
    @memset(cwd[0..], 0);
    _ = std.os.getcwd(&cwd) catch "";

    var base_path = std.mem.span(@as([*c]const u8, @ptrCast(cwd[0..])));

    while (true) {
        var res = try server.accept(.{
            .allocator = alloc,
            .header_strategy = .{.dynamic = 1024*10}
        });
        defer res.deinit();

        std.debug.print("Request made!\n", .{});

        var request_count:u32 = 0;

        while (res.reset() != .closing) {
            std.debug.print("Waiting for request...\n", .{});

            // FIXME: The wait functions internatlly tries to read from a socket
            // until it has a complete request header. Unfortunatelly it gets stuck
            // trying to fill a buffer but the client is already waiting for response,
            // this locks the function because its waiting for the client to finish the
            // request but the client belives it already finished a request. This could
            // be either due to incompatible protocol versions of HTTP between server and
            // client or it just might be a bug in std.http which is quite possible.
            //
            // NOTE: This has been temporarily fixed by providing the client with "connection: close"
            // response header. It forces the client to reinstantiate a new connection to the server
            // after every response.
            res.wait() catch |err| switch (err) {
                error.HttpHeadersInvalid => break,
                error.HttpHeadersExceededSizeLimit => {
                    res.status = .request_header_fields_too_large;
                    res.do() catch break;
                    break;
                },
                else => {
                    res.status = .bad_request;
                    res.do() catch break;
                    break;
                },
            };

            request_count += 1;

            std.debug.print("Request count: {}\n", .{request_count});
            std.debug.print("Request received!\n", .{});

            const request = res.request;

            std.debug.print("target: {s}\n", .{request.target});

            if(request.method != .GET) {
                std.debug.print("Unsupported request method!\n", .{});
                break;
            }

            // FIXME: Make sure file system resources are locked while they
            // are being retrived to avoid race conditions.
            if(Resource.locate(base_path, request.target)) |rsrc| {

                res.status = .ok;
                // FIXME: transfer encoding should corespond to prefer method used by client.

                if(rsrc.resource_size) |length| {
                    res.transfer_encoding = .{.content_length = length};
                }
                else {
                    res.transfer_encoding = .chunked;
                }
                var writer = res.writer();

                try res.headers.append("cache-control", "no-cache");
                try res.headers.append("content-type", rsrc.content_type);
                try res.headers.append("connection", "close");

                std.debug.print("Sending http header!\n", .{});
                res.do() catch |err| {
                    std.debug.print("Failed to send a response header: {}\n", .{err});
                    break;
                };

                rsrc.send(writer) catch |err| {
                    std.debug.print("Failed to sending a response body: {}\n", .{err});
                    break;
                };

                std.debug.print("Sent file: {s}\n", .{request.target});
            }
            else |_| {
                std.debug.print("File not found: {s}", .{request.target});
                res.status = .not_found;
                res.transfer_encoding = .chunked;
                try res.do();
            }

            res.finish() catch |err| {
                std.debug.print("Failed to finishing a response: {}\n", .{err});
                break;
            };
            std.debug.print("Finished a request.\n", .{});

        }
    }
}
