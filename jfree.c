/******************************************************************************
 *								              *	
 * JFree ARM Heap Analyzer						      *
 * 									      *
 * 	Julio Auto 			 <julio *noSPAM* julioauto.com>       *
 *	Rodrigo Rubira Branco (BSDaemon) <rodrigo *noSPAM* kernelhacking.com> *
 *****************************************************************************/

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <signal.h>


/*********************************************************************
 * ARM Stack Unwinder Section
 *********************************************************************/
#include "client.h"

#define JFREE_UNWIND(results)                  \
    Int32 sp;                                  \
    results.frameCount = 0;                    \
    asm volatile("mov %0, r13" : "=r" (sp));   \
    UnwindStart(sp, &cliCallbacks, &results); // fprintf(stderr, "FC: %d\n", results.frameCount);

/*********************************************************************
 * END of ARM Stack Unwinder Section
 *********************************************************************/



static void my_init_hook(void);

void (*__malloc_initialize_hook) (void) = my_init_hook;

static void *(*old_malloc_hook)(size_t, const void *);
static void *(*old_realloc_hook)(void*, size_t, const void *);
static void (*old_free_hook)(void*, const void *);

static void *my_malloc_hook(size_t, const void *);
static void *my_realloc_hook(void*, size_t, const void *);
static void my_free_hook(void*, const void *);

#define MALLOC_INTO(size, ret)         \
    __malloc_hook = old_malloc_hook;   \
    ret = malloc(size);                \
    old_malloc_hook = __malloc_hook;   \
    __malloc_hook = my_malloc_hook;
    
#define REALLOC_INTO(ptr, size, ret)   \
    __realloc_hook = old_realloc_hook; \
    ret = realloc(ptr, size);          \
    old_realloc_hook = __realloc_hook; \
    __realloc_hook = my_realloc_hook;
    
#define FREE(ptr)                      \
    __free_hook = old_free_hook;       \
    free(ptr);                         \
    old_free_hook = __free_hook;       \
    __free_hook = my_free_hook;


typedef struct _node_t
{
    unsigned int ptr;
    size_t size;
    unsigned int caller;
    unsigned int top_caller;
    unsigned int top_top_caller;
    struct _node_t *next;
} node_t;

node_t *mylist = NULL;


typedef struct _simple_node_t
{
    unsigned int ptr;
    struct _simple_node_t *next;
} simple_node_t;

#ifdef ENABLE_DBL_FREE_CHK
simple_node_t *freedlist = NULL;
#endif

void add_to_freed(unsigned int ptr)
{
#ifdef ENABLE_DBL_FREE_CHK
    simple_node_t *newnode;
    MALLOC_INTO(sizeof(simple_node_t), newnode);
    
    newnode->ptr = (unsigned int) ptr;
    newnode->next = freedlist;
    freedlist = newnode;
#endif
}

int once_freed(unsigned int ptr)
{
#ifdef ENABLE_DBL_FREE_CHK
    simple_node_t *cur = freedlist;
    while (cur)
    {
        if (cur->ptr == ptr)
            return 1;

        cur = cur->next;
    }

#endif
    return 0;
}


char logname[16];
unsigned int pid = 0;
unsigned long max_mem_usage = 0;
unsigned long cur_mem_usage = 0;
unsigned int invalid_usage = 0;
unsigned int jfree_on = 1;

int remove_node(unsigned int ptr)
{
    node_t *cur = mylist;

    if (cur && cur->ptr == ptr)
    {
        mylist = cur->next;

        if (!invalid_usage)
            if ((cur_mem_usage - cur->size) > cur_mem_usage)
                invalid_usage = 1;
        
        cur_mem_usage -= cur->size;
        
        FREE(cur);
        add_to_freed(ptr);
        return 1;
    }

    while (cur && cur->next)
    {
        if (cur->next->ptr == ptr)
        {
            node_t *tmp = cur->next;
            cur->next = cur->next->next;
            
            if (!invalid_usage)
                if ((cur_mem_usage - tmp->size) > cur_mem_usage)
                    invalid_usage = 1;
            
            cur_mem_usage -= tmp->size;

            FREE(tmp);
            add_to_freed(ptr);
            return 1;
        }
        cur = cur->next;
    }

    return 0;
}

void add_node(unsigned int ptr, size_t size, unsigned int caller,
                unsigned int top_caller, unsigned int top_top_caller)
{
    node_t *newnode;
    MALLOC_INTO(sizeof(node_t), newnode);
    
    newnode->ptr = ptr;
    newnode->size = size;
    newnode->caller = caller;
    newnode->top_caller = top_caller;
    newnode->top_top_caller = top_top_caller;
    newnode->next = mylist;

    mylist = newnode;

    if (invalid_usage)
        if ((cur_mem_usage + size) < cur_mem_usage)
            invalid_usage = 0;
    
    cur_mem_usage += size;
    
    if (!invalid_usage && (cur_mem_usage > max_mem_usage))
        max_mem_usage = cur_mem_usage;
}

FILE *mylogfd = 0;
void log_summary(void);

void show_cur_usage(int x)
{
    /*jfree_on = ~jfree_on;
    if (jfree_on)
        printf("JFree v0.01 is ON!\n");
    else
        printf("JFree v0.01 is OFF!\n");*/

    if (invalid_usage)
        printf("Invalid memory usage information. Please try again later.\n");
    else
        printf("Current memory usage: %lu bytes\n", cur_mem_usage);

}

static void my_init_hook()
{
    pid = (unsigned int) getpid();

    sprintf(logname, "jfree.log%u", pid);

    signal(SIGINT, show_cur_usage);

    old_malloc_hook = __malloc_hook;
    __malloc_hook = my_malloc_hook;
        
    old_realloc_hook = __realloc_hook;
    __realloc_hook = my_realloc_hook;
    
    old_free_hook = __free_hook;
    __free_hook = my_free_hook;

    atexit(log_summary);
}

static void *
my_malloc_hook (size_t size, const void *caller)
{
    void *result;
    MALLOC_INTO(size, result);

    if (jfree_on && caller == 0x41568084)
    {
        /* Funny hack :> */
        if ((caller >= ((void*)my_realloc_hook)) 
            && (caller < ((void*)my_free_hook)))
            return result;
    
        CliStack results;
        JFREE_UNWIND(results);

        if (result) fprintf(stderr, "BT for 0x%08x: ", result); int i = 0; while (i < results.frameCount) { fprintf(stderr, "0x%08x ", results.address[i]); i++; }  fprintf(stderr, "\n");
        if (result)
            add_node((unsigned int) result, size, (unsigned int) caller,
                        results.frameCount>1?results.address[results.frameCount-2]:0,
                        results.frameCount?results.address[results.frameCount-1]:0);
    }
    
    return result;
}

static void *
my_realloc_hook (void *ptr, size_t size, const void *caller)
{
    void *result;
    REALLOC_INTO(ptr, size, result);

    if (jfree_on && caller == 0x41568084)
    {
    
        CliStack results;
        JFREE_UNWIND(results);
    
        if (result) fprintf(stderr, "BT for 0x%08x: ", result); int i = 0; while (i < results.frameCount) { fprintf(stderr, "0x%08x ", results.address[i]); i++; }  fprintf(stderr, "\n");
        if (result)
        {
            remove_node((unsigned int) ptr);
        
            add_node((unsigned int) result, size, (unsigned int) caller,
                        results.frameCount>1?results.address[results.frameCount-2]:0,
                        results.frameCount?results.address[results.frameCount-1]:0);
        }
    }
    
    return result;
}

static void
my_free_hook (void *ptr, const void *caller)
{
    FREE(ptr);

    if (jfree_on)
    {

        /* Funny hack :> */
        if ((caller >= ((void*)my_realloc_hook))
            && (caller < ((void*)my_free_hook)))
            return;

        if (!remove_node((unsigned int) ptr) && once_freed((unsigned int) ptr))
        {
            if (!mylogfd)
            {
                mylogfd = fopen(logname, "w");
                if (!mylogfd)
                    exit(1);
            }
        
            fprintf(mylogfd, "double free (0x%08x) called from 0x%08x\n", (unsigned int) ptr, (unsigned int) caller);
            fflush(mylogfd);
        }
    }
}

void log_summary(void)
{
    if (!mylogfd)
    {
        mylogfd = fopen(logname, "w");
        if (!mylogfd)
            exit(1);
    }
        
    node_t *cur = mylist;
    size_t total = 0;
    while (cur)
    {
        fprintf(mylogfd, "memory leaked at 0x%08x alloc'ed from (base: 0x%08x previous-to-top: 0x%08x top: 0x%08x)(%u bytes)\n", 
                        cur->ptr, cur->caller, cur->top_caller, cur->top_top_caller, cur->size);
        total += cur->size;
        cur = cur->next;
    }

    fprintf(mylogfd, "\nTotal leaked in PID (%u): %lu bytes\n", pid, (unsigned long) total);
    fprintf(mylogfd, "Maximum memory usage in PID (%u): %lu bytes\n\n", pid, max_mem_usage);
    fflush(mylogfd);
}

