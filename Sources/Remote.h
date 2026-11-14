//
//  Remote.h
//  untcc
//
//  Created by Sunny Young on 2026/11/13.
//

#pragma once

#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <objc/runtime.h>
#include <pthread.h>

typedef enum {
    UNTCCPending,
    UNTCCInstalled,
    UNTCCAlreadyInstalled,
    UNTCCUnsupported,
    UNTCCThreadFailed,
} UNTCCStatus;

typedef BOOL (*UNTCCEntitlementCheck)(id, SEL, id, id, unsigned long long);
typedef struct UNTCCContext UNTCCContext;

typedef struct {
    void *isa;
    int flags;
    int reserved;
    uintptr_t invoke;
    void *descriptor;
    UNTCCContext *context;
} UNTCCBlock;

struct UNTCCContext {
    volatile UNTCCStatus status;
    volatile int bootstrapComplete;
    int threadError;
    mach_port_t workerThread;
    uintptr_t install;
    uintptr_t check;

    int (*createThread)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
    pthread_t (*currentThread)(void);
    int (*detachThread)(pthread_t);
    mach_port_t (*currentMachThread)(void);
    Class (*getClass)(const char *);
    SEL (*registerSelector)(const char *);
    Method (*getMethod)(Class, SEL);
    unsigned int (*getArgumentCount)(Method);
    void (*getReturnType)(Method, char *, size_t);
    void (*getArgumentType)(Method, unsigned int, char *, size_t);
    IMP (*getImplementation)(Method);
    IMP (*setImplementation)(Method, IMP);
    IMP (*implementationWithBlock)(id);
    id (*getAssociation)(id, const void *);
    void (*setAssociation)(id, const void *, id, objc_AssociationPolicy);
    CFStringRef (*createString)(CFAllocatorRef, const char *, CFStringEncoding);
    BOOL (*sendBooleanMessage)(id, SEL, id);
    void *globalBlockClass;

    char className[32];
    char methodName[64];
    char markerName[32];
    char stringClassName[16];
    char kindSelectorName[24];
    char equalSelectorName[24];
    char entitlementName[64];
    char booleanType;

    Class stringClass;
    SEL methodSelector;
    SEL kindSelector;
    SEL equalSelector;
    CFStringRef allowedEntitlement;
    UNTCCEntitlementCheck original;
    struct {
        unsigned long reserved;
        unsigned long size;
    } descriptor;
    UNTCCBlock block;
};

void UNTCCRemoteStart(UNTCCContext *context);
void *UNTCCRemoteInstall(void *argument);
BOOL UNTCCRemoteCheck(UNTCCBlock *block, id process, id entitlement, id service, unsigned long long options);
