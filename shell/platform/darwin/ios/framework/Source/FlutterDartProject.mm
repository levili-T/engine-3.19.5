// Copyright 2013 The Flutter Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#define FML_USED_ON_EMBEDDER

#import "flutter/shell/platform/darwin/ios/framework/Source/FlutterDartProject_Internal.h"

#include <syslog.h>

#import <Metal/Metal.h>
#include <sstream>
#include <string>

#include "flutter/common/constants.h"
#include "flutter/common/task_runners.h"
#include "flutter/fml/mapping.h"
#include "flutter/fml/message_loop.h"
#include "flutter/fml/platform/darwin/scoped_nsobject.h"
#include "flutter/runtime/dart_vm.h"
#include "flutter/shell/common/shell.h"
#include "flutter/shell/common/switches.h"
#import "flutter/shell/platform/darwin/common/command_line.h"
#import "flutter/shell/platform/darwin/ios/framework/Headers/FlutterViewController.h"

#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach/mach.h>
#import <mach-o/dyld_images.h>
#import <mach-o/nlist.h>
#import <sys/sysctl.h>
#import <CommonCrypto/CommonCrypto.h>
#import <sys/syscall.h>
#import <sys/stat.h>
#import <dlfcn.h>
#import <mach-o/fat.h>
#include <mach-o/loader.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
typedef struct fat_arch_64 fat_arch_t;
#define MH_MAGIC_T MH_MAGIC_64
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#define SYS_lstat_t SYS_lstat64
#define RET 0xd65f03c0
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
typedef struct fat_arch fat_arch_t
#define MH_MAGIC_T MH_MAGIC
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#define SYS_lstat_t SYS_lstat
#define RET 0x0
#endif

FLUTTER_ASSERT_NOT_ARC

extern "C" {
#if FLUTTER_RUNTIME_MODE == FLUTTER_RUNTIME_MODE_DEBUG
    // Used for debugging dart:* sources.
    extern const uint8_t kPlatformStrongDill[];
    extern const intptr_t kPlatformStrongDillSize;
#endif
}

static const char* kApplicationKernelSnapshotFileName = "kernel_blob.bin";

static BOOL DoesHardwareSupportWideGamut() {
    static BOOL result = NO;
    static dispatch_once_t once_token = 0;
    dispatch_once(&once_token, ^{
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (@available(iOS 13.0, *)) {
            // MTLGPUFamilyApple2 = A9/A10
            result = [device supportsFamily:MTLGPUFamilyApple2];
        } else {
            // A9/A10 on iOS 10+
            result = [device supportsFeatureSet:MTLFeatureSet_iOS_GPUFamily3_v2];
        }
        [device release];
    });
    return result;
}

mach_header_t * Lmc_mappingHotpatch(const char *path, intptr_t* mappingSize) {
    // 打开文件
    mach_header_t *baseAddr = NULL;
    int fd = -1;
    *mappingSize = 0;
    
    do
    {
        fd = open(path, O_RDONLY);
        if (fd == -1) {
            syslog(LOG_ALERT, "open hot patch faild! err:%d", errno);
            break;
        }

        // 获取文件大小
        struct stat stat = {0};
        int ret = fstat(fd, &stat);
        if (ret == -1) {
            syslog(LOG_ALERT, "fstat hot patch failed! err:%d", errno);
            break;
        }

        if(stat.st_size < 0x2000) {
            syslog(LOG_ALERT, "hot patch file size is too small");
            break;
        }

        // 读取fat_header
        fat_header fatHader = {0};
        ssize_t readSize = read(fd, &fatHader, sizeof(fat_header));
        if (readSize == -1) {
            syslog(LOG_ALERT, "read hot patch failed! err:%d", errno);
            break;
        }

        // 判断是否是fat文件
        if(fatHader.magic != FAT_CIGAM) {
            syslog(LOG_ALERT, "hot patch file is not fat file");
            break;
        }

        // 只支持单一架构
        int archCount = OSSwapBigToHostInt32(fatHader.nfat_arch);
        if(archCount != 1) {
            syslog(LOG_ALERT, "hot patch file has no arch");
            break;
        }

        // 读取fat_arch
        fat_arch fatArch = {0};
        readSize = read(fd, &fatArch, sizeof(fat_arch));
        if (readSize == -1) {
            syslog(LOG_ALERT, "read hot patch failed! err:%d", errno);
            break;
        }

        // 判断是否是arm64
        int32_t cputype = OSSwapBigToHostInt32(fatArch.cputype);
        if(cputype != CPU_TYPE_ARM64) {
            syslog(LOG_ALERT, "hot patch file is not arm64");
            break;
        }

        // 读取mach_header
        size_t offset = OSSwapBigToHostInt32(fatArch.offset);
        size_t size = OSSwapBigToHostInt32((uint32_t)fatArch.size);
        if(offset + size > (size_t)stat.st_size) {
            syslog(LOG_ALERT, "hot patch file size is wrong!");
            break;
        }

        // 映射文件
        baseAddr = (mach_header_t*)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, offset);
        if (baseAddr == MAP_FAILED) {
            syslog(LOG_ALERT, "mmap hot patch failed! err:%d", errno);
            break;
        }

        // 判断是否是macho文件
        if(baseAddr->magic != MH_MAGIC_T) {
            syslog(LOG_ALERT, "hot patch file is not macho file");
            baseAddr = NULL;
            break;
        }
        
        *mappingSize = (intptr_t)size;
        syslog(LOG_INFO, "mmap hot patch success! header:%p", baseAddr);
    }while (NO);

    if(baseAddr == NULL && fd != -1) {
        close(fd);
    }

    return baseAddr;
}

intptr_t yps_dragon_func_addr(const mach_header_t*header, const char* funcName)
{
    if(header->magic != MH_MAGIC_T)
    {
        return 0;
    }

    if(header->ncmds== 0)
    {
        return 0;
    }
    
    segment_command_t* cur_seg_cmd;
    segment_command_t* linkedit_segment = NULL;
    segment_command_t* text_segment = NULL;
    struct symtab_command* symtab_cmd = NULL;
    struct dysymtab_command* dysymtab_cmd = NULL;
    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    for(uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize)
    {
        cur_seg_cmd = (segment_command_t*)cur;
        if(cur_seg_cmd->cmd== LC_SEGMENT_ARCH_DEPENDENT)
        {
            if(strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0)
            {
                linkedit_segment = cur_seg_cmd;
            }
            else if(strcmp(cur_seg_cmd->segname, SEG_TEXT) == 0)
            {
                text_segment = cur_seg_cmd;
            }
        }
        else if(cur_seg_cmd->cmd== LC_SYMTAB)
        {
            symtab_cmd = (struct symtab_command*)cur_seg_cmd;
        }
        else if(cur_seg_cmd->cmd== LC_DYSYMTAB)
        {
            dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
        }
    }

    if(!symtab_cmd || !dysymtab_cmd || !linkedit_segment || !text_segment ||
       !dysymtab_cmd->nindirectsyms|| !symtab_cmd->nsyms)
    {
        //return 0;
    }

    // 计算ALSR的偏移
    uintptr_t slide = (uintptr_t)header - text_segment->vmaddr;
    uintptr_t linkedit_base = (uintptr_t)slide; // + linkedit_segment->vmaddr- linkedit_segment->fileoff;

    // 计算symbol/string table的基地址
    nlist_t* symtab = (nlist_t*)(linkedit_base + symtab_cmd->symoff);
    char* strtab = (char*)(linkedit_base + symtab_cmd->stroff);

    // 最终返回的函数地址
    intptr_t value = 0;
    for(uint i = 0; i < symtab_cmd->nsyms; i++)
    {
        if(symtab[i].n_sect== 0)
        {
            continue;
        }

        char *name = strtab + symtab[i].n_un.n_strx;
        if(strcmp(name, funcName) == 0)
        {
            value = symtab[i].n_value+ slide;
            break;;
        }
    }

    return value;
}

uint64_t Lmc_get_app_mapping_size(mach_header_t** appBaseAddr) {
    uint64_t total_size = 0;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char* image_name = _dyld_get_image_name(i);
        if (strcasestr(image_name, "App.framework") == NULL) {
            continue;
        }
        
        mach_header_t* header = (mach_header_t*)_dyld_get_image_header(i);
        *appBaseAddr = header;
        if (header->magic == MH_MAGIC_64) {
            struct load_command* cmd = (struct load_command*)(header + 1);
            for (uint32_t j = 0; j < header->ncmds; j++) {
                if (cmd->cmd == LC_SEGMENT_64) {
                    struct segment_command_64* segment = (struct segment_command_64*)cmd;
                    total_size += segment->vmsize;
                }
                cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
            }
        }
    }
    return total_size;
}

flutter::Settings FLTDefaultSettingsForBundle(NSBundle* bundle, NSProcessInfo* processInfoOrNil) {
    auto command_line = flutter::CommandLineFromNSProcessInfo(processInfoOrNil);
    
    // Precedence:
    // 1. Settings from the specified NSBundle (except for enable-impeller).
    // 2. Settings passed explicitly via command-line arguments.
    // 3. Settings from the NSBundle with the default bundle ID.
    // 4. Settings from the main NSBundle and default values.
    
    NSBundle* mainBundle = FLTGetApplicationBundle();
    NSBundle* engineBundle = [NSBundle bundleForClass:[FlutterViewController class]];
    
    bool hasExplicitBundle = bundle != nil;
    if (bundle == nil) {
        bundle = FLTFrameworkBundleWithIdentifier([FlutterDartProject defaultBundleIdentifier]);
    }
    
    auto settings = flutter::SettingsFromCommandLine(command_line);
    
    settings.task_observer_add = [](intptr_t key, const fml::closure& callback) {
        fml::MessageLoop::GetCurrent().AddTaskObserver(key, callback);
    };
    
    settings.task_observer_remove = [](intptr_t key) {
        fml::MessageLoop::GetCurrent().RemoveTaskObserver(key);
    };
    
    settings.log_message_callback = [](const std::string& tag, const std::string& message) {
        // TODO(cbracken): replace this with os_log-based approach.
        // https://github.com/flutter/flutter/issues/44030
        std::stringstream stream;
        if (!tag.empty()) {
            stream << tag << ": ";
        }
        stream << message;
        std::string log = stream.str();
        syslog(LOG_ALERT, "%.*s", (int)log.size(), log.c_str());
    };
    
    // The command line arguments may not always be complete. If they aren't, attempt to fill in
    // defaults.
    
    // Flutter ships the ICU data file in the bundle of the engine. Look for it there.
    if (settings.icu_data_path.empty()) {
        NSString* icuDataPath = [engineBundle pathForResource:@"icudtl" ofType:@"dat"];
        if (icuDataPath.length > 0) {
            settings.icu_data_path = icuDataPath.UTF8String;
        }
    }
    
    if (flutter::DartVM::IsRunningPrecompiledCode()) {
        if (hasExplicitBundle) {
            NSString* executablePath = bundle.executablePath;
            if ([[NSFileManager defaultManager] fileExistsAtPath:executablePath]) {
                settings.application_library_path.push_back(executablePath.UTF8String);
            }
        }
        
        // No application bundle specified.  Try a known location from the main bundle's Info.plist.
        if (settings.application_library_path.empty()) {
            NSString* libraryName = [mainBundle objectForInfoDictionaryKey:@"FLTLibraryPath"];
            NSString* libraryPath = [mainBundle pathForResource:libraryName ofType:@""];
            if (libraryPath.length > 0) {
                NSString* executablePath = [NSBundle bundleWithPath:libraryPath].executablePath;
                if (executablePath.length > 0) {
                    settings.application_library_path.push_back(executablePath.UTF8String);
                }
            }
        }
        
        // In case the application bundle is still not specified, look for the App.framework in the
        // Frameworks directory.
        if (settings.application_library_path.empty()) {
            NSString* applicationFrameworkPath = [mainBundle pathForResource:@"Frameworks/App.framework"
                                                                      ofType:@""];
            if (applicationFrameworkPath.length > 0) {
                NSString* executablePath =
                [NSBundle bundleWithPath:applicationFrameworkPath].executablePath;
                
                if(settings.bForceSimulatorRun) // 强制先加载App.framework
                {
                    NSBundle* bundle = [NSBundle bundleWithPath:applicationFrameworkPath];
                    NSError* err = nil;
                    [bundle loadAndReturnError:&err];
                    if (err != nil) {
                        NSLog(@"Failed to load bundle: %@", err);
                    }
                }
                
                if (executablePath.length > 0) {
                    settings.application_library_path.push_back(executablePath.UTF8String);
                }
            }
        }
    }
    
    // 加载hotPath
    bool bHotPatch = false;
    NSString* hotPath = [mainBundle pathForResource:@"libApp" ofType:@"so"];
    if([NSFileManager.defaultManager fileExistsAtPath:hotPath])
    {
        intptr_t mappingSize = 0;
        mach_header_t* header = Lmc_mappingHotpatch(hotPath.UTF8String, &mappingSize);
        if(header != NULL)
        {
            // 获取函数地址
            settings.kDartVmSnapshotDataPtr = yps_dragon_func_addr(header, "_kDartVmSnapshotData");
            settings.kDartVmSnapshotInstructionsPtr = yps_dragon_func_addr(header, "_kDartVmSnapshotInstructions");
            settings.kDartIsolateSnapshotDataPtr = yps_dragon_func_addr(header, "_kDartIsolateSnapshotData");
            settings.kDartIsolateSnapshotInstructionsPtr = yps_dragon_func_addr(header, "_kDartIsolateSnapshotInstructions");
            syslog(LOG_INFO, "dlsym hotPath! vmdata:%p vmins:%p isoData:%p isoIns:%p", (void*)settings.kDartVmSnapshotDataPtr, (void*)settings.kDartVmSnapshotInstructionsPtr, (void*)settings.kDartIsolateSnapshotDataPtr, (void*)settings.kDartIsolateSnapshotInstructionsPtr);
            if(settings.kDartVmSnapshotDataPtr != 0 && settings.kDartVmSnapshotInstructionsPtr != 0 && settings.kDartIsolateSnapshotDataPtr != 0 && settings.kDartIsolateSnapshotInstructionsPtr != 0)
            {
                bHotPatch = true;
                Dart_SetAppMappingInfo((intptr_t)header, (intptr_t)mappingSize);
                Dart_SetHotPatchExcute(true);
                syslog(LOG_INFO, "dlsym hotPath real! appBaseAddr:%p appSize:%ld", header, (intptr_t)mappingSize);
            }
        }
    }
    
    settings.bForceSimulatorRun = true;
    if(bHotPatch == false && settings.bForceSimulatorRun)
    {
        Dart_SetHotPatchExcute(true);
        mach_header_t* appBaseAddr = NULL;
        
        NSString* applicationFrameworkPath = [mainBundle pathForResource:@"Frameworks/App.framework"
                                                                ofType:@""];
        if (applicationFrameworkPath.length > 0) {
            
            NSBundle* bundle = [NSBundle bundleWithPath:applicationFrameworkPath];
            NSError* err = nil;
            [bundle loadAndReturnError:&err];
            if (err != nil) {
                NSLog(@"Failed to load bundle: %@", err);
            }
            
        }
        
        uint64_t appSize = Lmc_get_app_mapping_size(&appBaseAddr);
        syslog(LOG_INFO, "dlsym hotPath! appBaseAddr:%p appSize:%llu", appBaseAddr, appSize);
        Dart_SetAppMappingInfo((intptr_t)appBaseAddr, (intptr_t)appSize);
    }

    // Checks to see if the flutter assets directory is already present.
    if (settings.assets_path.empty()) {
        NSString* assetsPath = FLTAssetsPathFromBundle(bundle);
        
        if (assetsPath.length == 0) {
            NSLog(@"Failed to find assets path for \"%@\"", bundle);
        } else {
            settings.assets_path = assetsPath.UTF8String;
            
            // Check if there is an application kernel snapshot in the assets directory we could
            // potentially use.  Looking for the snapshot makes sense only if we have a VM that can use
            // it.
            if (!flutter::DartVM::IsRunningPrecompiledCode()) {
                NSURL* applicationKernelSnapshotURL =
                [NSURL URLWithString:@(kApplicationKernelSnapshotFileName)
                       relativeToURL:[NSURL fileURLWithPath:assetsPath]];
                NSError* error;
                if ([applicationKernelSnapshotURL checkResourceIsReachableAndReturnError:&error]) {
                    settings.application_kernel_asset = applicationKernelSnapshotURL.path.UTF8String;
                } else {
                    NSLog(@"Failed to find snapshot at %@: %@", applicationKernelSnapshotURL.path, error);
                }
            }
        }
    }
    
    // Domain network configuration
    // Disabled in https://github.com/flutter/flutter/issues/72723.
    // Re-enable in https://github.com/flutter/flutter/issues/54448.
    settings.may_insecurely_connect_to_all_domains = true;
    settings.domain_network_policy = "";
    
    // Whether to enable wide gamut colors.
#if TARGET_OS_SIMULATOR
    // As of Xcode 14.1, the wide gamut surface pixel formats are not supported by
    // the simulator.
    settings.enable_wide_gamut = false;
    // Removes unused function warning.
    (void)DoesHardwareSupportWideGamut;
#else
    NSNumber* nsEnableWideGamut = [mainBundle objectForInfoDictionaryKey:@"FLTEnableWideGamut"];
    BOOL enableWideGamut =
    (nsEnableWideGamut ? nsEnableWideGamut.boolValue : YES) && DoesHardwareSupportWideGamut();
    settings.enable_wide_gamut = enableWideGamut;
#endif
    
    // TODO(dnfield): We should reverse the order for all these settings so that command line options
    // are preferred to plist settings. https://github.com/flutter/flutter/issues/124049
    // Whether to enable Impeller. If the command line explicitly
    // specified an option for this, ignore what's in the plist.
    if (!command_line.HasOption("enable-impeller")) {
        // Next, look in the app bundle.
        NSNumber* enableImpeller = [bundle objectForInfoDictionaryKey:@"FLTEnableImpeller"];
        if (enableImpeller == nil) {
            // If it isn't in the app bundle, look in the main bundle.
            enableImpeller = [mainBundle objectForInfoDictionaryKey:@"FLTEnableImpeller"];
        }
        // Change the default only if the option is present.
        if (enableImpeller != nil) {
            settings.enable_impeller = enableImpeller.boolValue;
        }
    }
    
    NSNumber* enableTraceSystrace = [mainBundle objectForInfoDictionaryKey:@"FLTTraceSystrace"];
    // Change the default only if the option is present.
    if (enableTraceSystrace != nil) {
        settings.trace_systrace = enableTraceSystrace.boolValue;
    }
    
    NSNumber* enableDartProfiling = [mainBundle objectForInfoDictionaryKey:@"FLTEnableDartProfiling"];
    // Change the default only if the option is present.
    if (enableDartProfiling != nil) {
        settings.enable_dart_profiling = enableDartProfiling.boolValue;
    }
    
    // Leak Dart VM settings, set whether leave or clean up the VM after the last shell shuts down.
    NSNumber* leakDartVM = [mainBundle objectForInfoDictionaryKey:@"FLTLeakDartVM"];
    // It will change the default leak_vm value in settings only if the key exists.
    if (leakDartVM != nil) {
        settings.leak_vm = leakDartVM.boolValue;
    }
    
#if FLUTTER_RUNTIME_MODE == FLUTTER_RUNTIME_MODE_DEBUG
    // There are no ownership concerns here as all mappings are owned by the
    // embedder and not the engine.
    auto make_mapping_callback = [](const uint8_t* mapping, size_t size) {
        return [mapping, size]() { return std::make_unique<fml::NonOwnedMapping>(mapping, size); };
    };
    
    settings.dart_library_sources_kernel =
    make_mapping_callback(kPlatformStrongDill, kPlatformStrongDillSize);
#endif  // FLUTTER_RUNTIME_MODE == FLUTTER_RUNTIME_MODE_DEBUG
    
    // If we even support setting this e.g. from the command line or the plist,
    // we should let the user override it.
    // Otherwise, we want to set this to a value that will avoid having the OS
    // kill us. On most iOS devices, that happens somewhere near half
    // the available memory.
    // The VM expects this value to be in megabytes.
    if (settings.old_gen_heap_size <= 0) {
        settings.old_gen_heap_size = std::round([NSProcessInfo processInfo].physicalMemory * .48 /
                                                flutter::kMegaByteSizeInBytes);
    }
    
    // This is the formula Android uses.
    // https://android.googlesource.com/platform/frameworks/base/+/39ae5bac216757bc201490f4c7b8c0f63006c6cd/libs/hwui/renderthread/CacheManager.cpp#45
    CGFloat scale = [UIScreen mainScreen].scale;
    CGFloat screenWidth = [UIScreen mainScreen].bounds.size.width * scale;
    CGFloat screenHeight = [UIScreen mainScreen].bounds.size.height * scale;
    settings.resource_cache_max_bytes_threshold = screenWidth * screenHeight * 12 * 4;
    
    // Whether to enable ios embedder api.
    NSNumber* enable_embedder_api =
    [mainBundle objectForInfoDictionaryKey:@"FLTEnableIOSEmbedderAPI"];
    // Change the default only if the option is present.
    if (enable_embedder_api) {
        settings.enable_embedder_api = enable_embedder_api.boolValue;
    }
    
    return settings;
}

@implementation FlutterDartProject {
    flutter::Settings _settings;
}

// This property is marked unavailable on iOS in the common header.
// That doesn't seem to be enough to prevent this property from being synthesized.
// Mark dynamic to avoid warnings.
@dynamic dartEntrypointArguments;

#pragma mark - Override base class designated initializers

- (instancetype)init {
    return [self initWithPrecompiledDartBundle:nil];
}

#pragma mark - Designated initializers

- (instancetype)initWithPrecompiledDartBundle:(nullable NSBundle*)bundle {
    self = [super init];
    
    if (self) {
        _settings = FLTDefaultSettingsForBundle(bundle);
    }
    
    return self;
}

- (instancetype)initWithSettings:(const flutter::Settings&)settings {
    self = [self initWithPrecompiledDartBundle:nil];
    
    if (self) {
        _settings = settings;
    }
    
    return self;
}

#pragma mark - PlatformData accessors

- (const flutter::PlatformData)defaultPlatformData {
    flutter::PlatformData PlatformData;
    PlatformData.lifecycle_state = std::string("AppLifecycleState.detached");
    return PlatformData;
}

#pragma mark - Settings accessors

- (const flutter::Settings&)settings {
    return _settings;
}

- (flutter::RunConfiguration)runConfiguration {
    return [self runConfigurationForEntrypoint:nil];
}

- (flutter::RunConfiguration)runConfigurationForEntrypoint:(nullable NSString*)entrypointOrNil {
    return [self runConfigurationForEntrypoint:entrypointOrNil libraryOrNil:nil];
}

- (flutter::RunConfiguration)runConfigurationForEntrypoint:(nullable NSString*)entrypointOrNil
libraryOrNil:(nullable NSString*)dartLibraryOrNil {
    return [self runConfigurationForEntrypoint:entrypointOrNil
                                  libraryOrNil:dartLibraryOrNil
                                entrypointArgs:nil];
}

- (flutter::RunConfiguration)runConfigurationForEntrypoint:(nullable NSString*)entrypointOrNil
libraryOrNil:(nullable NSString*)dartLibraryOrNil
entrypointArgs:
(nullable NSArray<NSString*>*)entrypointArgs {
    auto config = flutter::RunConfiguration::InferFromSettings(_settings);
    if (dartLibraryOrNil && entrypointOrNil) {
        config.SetEntrypointAndLibrary(std::string([entrypointOrNil UTF8String]),
                                       std::string([dartLibraryOrNil UTF8String]));
        
    } else if (entrypointOrNil) {
        config.SetEntrypoint(std::string([entrypointOrNil UTF8String]));
    }
    
    if (entrypointArgs.count) {
        std::vector<std::string> cppEntrypointArgs;
        for (NSString* arg in entrypointArgs) {
            cppEntrypointArgs.push_back(std::string([arg UTF8String]));
        }
        config.SetEntrypointArgs(std::move(cppEntrypointArgs));
    }
    
    return config;
}

#pragma mark - Assets-related utilities

+ (NSString*)flutterAssetsName:(NSBundle*)bundle {
    if (bundle == nil) {
        bundle = FLTFrameworkBundleWithIdentifier([FlutterDartProject defaultBundleIdentifier]);
    }
    return FLTAssetPath(bundle);
}

+ (NSString*)domainNetworkPolicy:(NSDictionary*)appTransportSecurity {
    // https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity/nsexceptiondomains
    NSDictionary* exceptionDomains = [appTransportSecurity objectForKey:@"NSExceptionDomains"];
    if (exceptionDomains == nil) {
        return @"";
    }
    NSMutableArray* networkConfigArray = [[[NSMutableArray alloc] init] autorelease];
    for (NSString* domain in exceptionDomains) {
        NSDictionary* domainConfiguration = [exceptionDomains objectForKey:domain];
        // Default value is false.
        bool includesSubDomains =
        [[domainConfiguration objectForKey:@"NSIncludesSubdomains"] boolValue];
        bool allowsCleartextCommunication =
        [[domainConfiguration objectForKey:@"NSExceptionAllowsInsecureHTTPLoads"] boolValue];
        [networkConfigArray addObject:@[
            domain, includesSubDomains ? @YES : @NO, allowsCleartextCommunication ? @YES : @NO
        ]];
    }
    NSData* jsonData = [NSJSONSerialization dataWithJSONObject:networkConfigArray
                                                       options:0
                                                         error:NULL];
    return [[[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding] autorelease];
}

+ (bool)allowsArbitraryLoads:(NSDictionary*)appTransportSecurity {
    return [[appTransportSecurity objectForKey:@"NSAllowsArbitraryLoads"] boolValue];
}

+ (NSString*)lookupKeyForAsset:(NSString*)asset {
    return [self lookupKeyForAsset:asset fromBundle:nil];
}

+ (NSString*)lookupKeyForAsset:(NSString*)asset fromBundle:(nullable NSBundle*)bundle {
    NSString* flutterAssetsName = [FlutterDartProject flutterAssetsName:bundle];
    return [NSString stringWithFormat:@"%@/%@", flutterAssetsName, asset];
}

+ (NSString*)lookupKeyForAsset:(NSString*)asset fromPackage:(NSString*)package {
    return [self lookupKeyForAsset:asset fromPackage:package fromBundle:nil];
}

+ (NSString*)lookupKeyForAsset:(NSString*)asset
                   fromPackage:(NSString*)package
                    fromBundle:(nullable NSBundle*)bundle {
    return [self lookupKeyForAsset:[NSString stringWithFormat:@"packages/%@/%@", package, asset]
                        fromBundle:bundle];
}

+ (NSString*)defaultBundleIdentifier {
    return @"io.flutter.flutter.app";
}

- (BOOL)isWideGamutEnabled {
    return _settings.enable_wide_gamut;
}

- (BOOL)isImpellerEnabled {
    return _settings.enable_impeller;
}

@end
