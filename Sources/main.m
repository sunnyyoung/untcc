//
//  main.m
//  untcc
//
//  Created by Sunny Young on 2026/11/13.
//

#import <ApplicationServices/ApplicationServices.h>
#import <CoreGraphics/CoreGraphics.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <libproc.h>
#import <mach/mach_vm.h>
#import <mach-o/getsect.h>
#import <mach-o/ldsyms.h>
#import <objc/message.h>
#import <ptrauth.h>
#import <signal.h>
#import <unistd.h>

#import "Remote.h"

static volatile sig_atomic_t stopping;

static void handleSignal(int signalNumber) {
    stopping = 1;
}

static BOOL installHook(pid_t pid, NSString **message) {
    mach_port_t task = MACH_PORT_NULL;
    thread_act_t thread = MACH_PORT_NULL;
    thread_act_t conversionThread = MACH_PORT_NULL;
    mach_vm_address_t code = 0;
    mach_vm_address_t data = 0;
    mach_vm_address_t stack = 0;
    const mach_vm_size_t stackSize = 64 * 1024;
    unsigned long codeSize = 0;
    uint8_t *localCode = getsectiondata(&_mh_execute_header, "__TEXT", "__untcc", &codeSize);
    BOOL started = NO;
    BOOL finished = NO;
    BOOL installed = NO;
    const char *operation = "task_for_pid";
    kern_return_t error = task_for_pid(mach_task_self(), pid, &task);
    if (error != KERN_SUCCESS) goto cleanup;

    operation = "allocate code";
    error = mach_vm_allocate(task, &code, codeSize, VM_FLAGS_ANYWHERE);
    if (error != KERN_SUCCESS) goto cleanup;
    operation = "allocate context";
    error = mach_vm_allocate(task, &data, sizeof(UNTCCContext), VM_FLAGS_ANYWHERE);
    if (error != KERN_SUCCESS) goto cleanup;
    operation = "allocate stack";
    error = mach_vm_allocate(task, &stack, stackSize, VM_FLAGS_ANYWHERE);
    if (error != KERN_SUCCESS) goto cleanup;

    UNTCCContext context = {0};
    context.install = code + ((uintptr_t)ptrauth_strip(&UNTCCRemoteInstall, ptrauth_key_function_pointer) - (uintptr_t)localCode);
    context.check = code + ((uintptr_t)ptrauth_strip(&UNTCCRemoteCheck, ptrauth_key_function_pointer) - (uintptr_t)localCode);
    context.createThread = dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
    context.currentThread = pthread_self;
    context.detachThread = pthread_detach;
    context.currentMachThread = mach_thread_self;
    context.getClass = objc_getClass;
    context.registerSelector = sel_registerName;
    context.getMethod = class_getInstanceMethod;
    context.getArgumentCount = method_getNumberOfArguments;
    context.getReturnType = method_getReturnType;
    context.getArgumentType = method_getArgumentType;
    context.getImplementation = method_getImplementation;
    context.setImplementation = method_setImplementation;
    context.implementationWithBlock = imp_implementationWithBlock;
    context.getAssociation = objc_getAssociatedObject;
    context.setAssociation = objc_setAssociatedObject;
    context.createString = CFStringCreateWithCString;
    context.sendBooleanMessage = (BOOL (*)(id, SEL, id))objc_msgSend;
    context.globalBlockClass = dlsym(RTLD_DEFAULT, "_NSConcreteGlobalBlock");
    strlcpy(context.className, "TCCDProcess", sizeof(context.className));
    strlcpy(context.methodName, "hasEntitlement:containsService:options:", sizeof(context.methodName));
    strlcpy(context.markerName, "com.sunnyyoung.untcc", sizeof(context.markerName));
    strlcpy(context.stringClassName, "NSString", sizeof(context.stringClassName));
    strlcpy(context.kindSelectorName, "isKindOfClass:", sizeof(context.kindSelectorName));
    strlcpy(context.equalSelectorName, "isEqualToString:", sizeof(context.equalSelectorName));
    strlcpy(context.entitlementName, "com.apple.private.tcc.allow", sizeof(context.entitlementName));
    context.booleanType = @encode(BOOL)[0];

    operation = "write code";
    error = mach_vm_write(task, code, (vm_offset_t)localCode, (mach_msg_type_number_t)codeSize);
    if (error != KERN_SUCCESS) goto cleanup;
    operation = "write context";
    error = mach_vm_write(task, data, (vm_offset_t)&context, sizeof(context));
    if (error != KERN_SUCCESS) goto cleanup;
    operation = "protect code";
    error = mach_vm_protect(task, code, codeSize, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (error != KERN_SUCCESS) goto cleanup;

    // Convert the PC into the target's arm64e thread-state representation.
    arm_thread_state64_t state = {0};
    arm_thread_state64_t converted = {0};
    mach_msg_type_number_t stateCount = ARM_THREAD_STATE64_COUNT;
    uintptr_t entry = code + ((uintptr_t)ptrauth_strip(&UNTCCRemoteStart, ptrauth_key_function_pointer) - (uintptr_t)localCode);
    arm_thread_state64_set_pc_fptr(state, ptrauth_sign_unauthenticated((void *)entry, ptrauth_key_function_pointer, 0));
    arm_thread_state64_set_sp(state, stack + stackSize);
    state.__x[0] = data;
    operation = "create conversion thread";
    error = thread_create(task, &conversionThread);
    if (error != KERN_SUCCESS) goto cleanup;
    operation = "convert thread state";
    error = thread_convert_thread_state(conversionThread, THREAD_CONVERT_THREAD_STATE_FROM_SELF,
                                       ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT,
                                       (thread_state_t)&converted, &stateCount);
    if (error != KERN_SUCCESS) goto cleanup;
    thread_terminate(conversionThread);
    mach_port_deallocate(mach_task_self(), conversionThread);
    conversionThread = MACH_PORT_NULL;

    operation = "start remote thread";
    error = thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&converted, stateCount, &thread);
    if (error != KERN_SUCCESS) goto cleanup;
    started = YES;

    for (unsigned int attempt = 0; attempt < 1000; attempt++) {
        mach_vm_size_t bytesRead = 0;
        operation = "read hook status";
        error = mach_vm_read_overwrite(task, data, sizeof(context), (mach_vm_address_t)&context, &bytesRead);
        if (error != KERN_SUCCESS) goto cleanup;
        if (context.bootstrapComplete && thread != MACH_PORT_NULL) {
            operation = "finish bootstrap thread";
            error = thread_terminate(thread);
            if (error != KERN_SUCCESS) goto cleanup;
            mach_port_deallocate(mach_task_self(), thread);
            thread = MACH_PORT_NULL;
            mach_vm_deallocate(task, stack, stackSize);
            stack = 0;
        }
        if (context.bootstrapComplete && context.status != UNTCCPending) {
            if (context.workerThread != MACH_PORT_NULL) {
                mach_port_type_t type = 0;
                operation = "read worker thread state";
                error = mach_port_type(task, context.workerThread, &type);
                if (error != KERN_SUCCESS) goto cleanup;
                if (!(type & MACH_PORT_TYPE_DEAD_NAME)) {
                    usleep(10000);
                    continue;
                }
                operation = "release worker thread right";
                error = mach_port_deallocate(task, context.workerThread);
                if (error != KERN_SUCCESS) goto cleanup;
            }
            finished = YES;
            installed = context.status == UNTCCInstalled || context.status == UNTCCAlreadyInstalled;
            if (context.status == UNTCCUnsupported) {
                *message = @"unsupported TCCDProcess entitlement method";
            } else if (context.status == UNTCCThreadFailed) {
                *message = [NSString stringWithFormat:@"pthread setup failed: %s", strerror(context.threadError)];
            }
            break;
        }
        usleep(10000);
    }
    if (!finished) *message = @"hook installation timed out";

cleanup:
    if (error != KERN_SUCCESS) {
        *message = [NSString stringWithFormat:@"%s: %s", operation, mach_error_string(error)];
    }
    if (conversionThread != MACH_PORT_NULL) {
        thread_terminate(conversionThread);
        mach_port_deallocate(mach_task_self(), conversionThread);
    }
    // Installed hooks retain their code and context; completed no-op/error installs do not.
    if (!started || (finished && context.status != UNTCCInstalled)) {
        if (stack) mach_vm_deallocate(task, stack, stackSize);
        if (data) mach_vm_deallocate(task, data, sizeof(UNTCCContext));
        if (code) mach_vm_deallocate(task, code, codeSize);
    }
    if (thread != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), thread);
    if (task != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), task);
    return installed;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc == 2 && strcmp(argv[1], "probe") == 0) {
            BOOL accessibility = AXIsProcessTrusted();
            BOOL screenCapture = CGPreflightScreenCaptureAccess();
            printf("{\"accessibility\":%s,\"screenCapture\":%s}\n",
                   accessibility ? "true" : "false", screenCapture ? "true" : "false");
            return accessibility && screenCapture ? EXIT_SUCCESS : EXIT_FAILURE;
        }
        if (argc == 2 && strcmp(argv[1], "--version") == 0) {
            puts("untcc " UNTCC_VERSION);
            return EXIT_SUCCESS;
        }
        if (argc == 2 && strcmp(argv[1], "--help") == 0) {
            puts("Usage: untcc [probe | --help | --version]\n\n"
                 "Run without a command as root to maintain an in-memory TCC bypass in tccd.\n"
                 "Injection requires Apple silicon, macOS 15 or later, and disabled SIP.\n"
                 "On macOS 15, the -arm64e_preview_abi boot argument is required:\n"
                 "  sudo nvram boot-args=\"-arm64e_preview_abi\"\n"
                 "Stopping untcc leaves existing hooks active until tccd restarts.\n\n"
                 "probe reports current-process Accessibility and Screen Recording access as JSON.\n"
                 "It does not request access or require root; exits 0 if both are allowed, otherwise 1.");
            return EXIT_SUCCESS;
        }
        if (argc != 1) {
            fputs("Usage: untcc [probe | --help | --version]\n", stderr);
            return EXIT_FAILURE;
        }
        if (geteuid() != 0) {
            fputs("untcc: root required\n", stderr);
            return EXIT_FAILURE;
        }

        signal(SIGTERM, handleSignal);
        signal(SIGINT, handleSignal);
        setvbuf(stdout, NULL, _IOLBF, 0);
        NSMutableSet<NSNumber *> *attempted = [NSMutableSet set];
        puts("untcc: watching tccd");

        while (!stopping) {
            @autoreleasepool {
                int capacity = proc_listallpids(NULL, 0);
                if (capacity <= 0) {
                    perror("untcc: enumerate processes");
                    return EXIT_FAILURE;
                }
                NSMutableData *storage = [NSMutableData dataWithLength:(NSUInteger)capacity * 2 * sizeof(pid_t)];
                pid_t *pids = storage.mutableBytes;
                int count = proc_listallpids(pids, (int)storage.length);
                if (count < 0) {
                    perror("untcc: enumerate processes");
                    return EXIT_FAILURE;
                }
                NSMutableSet<NSNumber *> *live = [NSMutableSet set];
                for (int index = 0; index < count && !stopping; index++) {
                    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
                    if (proc_pidpath(pids[index], path, sizeof(path)) <= 0 ||
                        strcmp(path, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd") != 0) continue;
                    NSNumber *pid = @(pids[index]);
                    [live addObject:pid];
                    if ([attempted containsObject:pid]) continue;

                    NSString *message = nil;
                    if (installHook(pid.intValue, &message)) {
                        printf("untcc: ready pid=%d\n", pid.intValue);
                    } else {
                        fprintf(stderr, "untcc: failed pid=%d: %s\n", pid.intValue, message.UTF8String);
                        return EXIT_FAILURE;
                    }
                    [attempted addObject:pid];
                }
                [attempted intersectSet:live];
            }
            if (!stopping) sleep(2);
        }
        puts("untcc: stopped; existing hooks remain until tccd restarts");
        return EXIT_SUCCESS;
    }
}
