//
//  Remote.m
//  untcc
//
//  Created by Sunny Young on 2026/11/13.
//

#include "Remote.h"
#include <ptrauth.h>

// These routines are copied together into tccd. All external addresses and data
// arrive through the context; no literals, imports, ARC, or stack guards belong here.
#define REMOTE_CODE __attribute__((section("__TEXT,__untcc,regular,pure_instructions"), used, noinline))

REMOTE_CODE void UNTCCRemoteStart(UNTCCContext *context) {
    // Function pointers copied from untcc must be signed with tccd's PAC key.
#define RESIGN_FUNCTION(field) context->field = ptrauth_sign_unauthenticated( \
    ptrauth_strip(context->field, ptrauth_key_function_pointer), ptrauth_key_function_pointer, 0)
    RESIGN_FUNCTION(createThread);
    RESIGN_FUNCTION(currentThread);
    RESIGN_FUNCTION(detachThread);
    RESIGN_FUNCTION(currentMachThread);
    RESIGN_FUNCTION(getClass);
    RESIGN_FUNCTION(registerSelector);
    RESIGN_FUNCTION(getMethod);
    RESIGN_FUNCTION(getArgumentCount);
    RESIGN_FUNCTION(getReturnType);
    RESIGN_FUNCTION(getArgumentType);
    RESIGN_FUNCTION(getImplementation);
    RESIGN_FUNCTION(setImplementation);
    RESIGN_FUNCTION(implementationWithBlock);
    RESIGN_FUNCTION(getAssociation);
    RESIGN_FUNCTION(setAssociation);
    RESIGN_FUNCTION(createString);
    RESIGN_FUNCTION(sendBooleanMessage);
#undef RESIGN_FUNCTION

    void *(*entry)(void *) = ptrauth_sign_unauthenticated((void *)context->install, ptrauth_key_function_pointer, 0);
    pthread_t worker;
    int threadError = context->createThread(&worker, NULL, entry, context);
    if (threadError != 0) {
        context->threadError = threadError;
        __atomic_store_n(&context->status, UNTCCThreadFailed, __ATOMIC_RELEASE);
    }
    // A raw Mach thread has no pthread TLS. The injector terminates it after
    // pthread creation returns; making a MIG call here would access missing TLS.
    __atomic_store_n(&context->bootstrapComplete, 1, __ATOMIC_RELEASE);
    for (;;) __asm__ volatile("wfe");
}

REMOTE_CODE void *UNTCCRemoteInstall(void *argument) {
    UNTCCContext *context = argument;
    // Keep a send right so the injector can observe thread death before unmapping code.
    context->workerThread = context->currentMachThread();
    int threadError = context->detachThread(context->currentThread());
    if (threadError != 0) {
        context->threadError = threadError;
        __atomic_store_n(&context->status, UNTCCThreadFailed, __ATOMIC_RELEASE);
        return NULL;
    }

    Class cls = context->getClass(context->className);
    SEL marker = context->registerSelector(context->markerName);
    if (cls && context->getAssociation((id)cls, marker)) {
        __atomic_store_n(&context->status, UNTCCAlreadyInstalled, __ATOMIC_RELEASE);
        return NULL;
    }

    context->methodSelector = context->registerSelector(context->methodName);
    Method method = cls ? context->getMethod(cls, context->methodSelector) : NULL;
    char returnType[8] = {0};
    char optionsType[8] = {0};
    if (method) {
        context->getReturnType(method, returnType, sizeof(returnType));
        context->getArgumentType(method, 4, optionsType, sizeof(optionsType));
    }
    if (!method || context->getArgumentCount(method) != 5 ||
        returnType[0] != context->booleanType || returnType[1] != '\0' ||
        optionsType[0] != 'Q' || optionsType[1] != '\0') {
        __atomic_store_n(&context->status, UNTCCUnsupported, __ATOMIC_RELEASE);
        return NULL;
    }

    context->stringClass = context->getClass(context->stringClassName);
    context->kindSelector = context->registerSelector(context->kindSelectorName);
    context->equalSelector = context->registerSelector(context->equalSelectorName);
    context->allowedEntitlement = context->createString(NULL, context->entitlementName, kCFStringEncodingUTF8);

    context->original = (UNTCCEntitlementCheck)context->getImplementation(method);

    context->descriptor.reserved = 0;
    context->descriptor.size = sizeof(UNTCCBlock);
    context->block.isa = context->globalBlockClass;
    context->block.flags = 1 << 28; // BLOCK_IS_GLOBAL: the mapping lives as long as tccd.
    context->block.descriptor = &context->descriptor;
    context->block.context = context;

    // arm64e block invoke pointers are signed with their storage address.
    context->block.invoke = (uintptr_t)ptrauth_sign_unauthenticated(
        (void *)context->check, ptrauth_key_block_function, &context->block.invoke);

    IMP hook = context->implementationWithBlock((id)&context->block);
    context->setImplementation(method, hook);
    context->setAssociation((id)cls, marker, (id)context->allowedEntitlement, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    __atomic_store_n(&context->status, UNTCCInstalled, __ATOMIC_RELEASE);
    return NULL;
}

REMOTE_CODE BOOL UNTCCRemoteCheck(UNTCCBlock *block, id process, id entitlement, id service, unsigned long long options) {
    UNTCCContext *context = block->context;
    if (context->sendBooleanMessage(entitlement, context->kindSelector, (id)context->stringClass) &&
        context->sendBooleanMessage(entitlement, context->equalSelector, (id)context->allowedEntitlement)) {
        return YES;
    }
    return context->original(process, context->methodSelector, entitlement, service, options);
}
