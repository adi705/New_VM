/*
 * memory.c
 * Note:
 * There is no separate swap area. When a data page is swapped out,
 * it is stored in the location it was loaded from in the process'
 * image. This means it's impossible to start two processes from the
 * same image without screwing up the running. It also means the
 * disk image is read once. And that we cannot use the program disk.
 *
 * Best viewed with tabs set to 4 spaces.
 */

#include "common.h"
#include "interrupt.h"
#include "kernel.h"
#include "memory.h"
#include "scheduler.h"
#include "thread.h"
#include "tlb.h"
#include "usb/scsi.h"
#include "util.h"


/* Use virtual address to get index in page directory.  */
inline uint32_t get_directory_index(uint32_t vaddr);

/*
 * Use virtual address to get index in a page table.  The bits are
 * masked, so we essentially get a modulo 1024 index.  The selection
 * of which page table to index into is done with
 * get_directory_index().
 */
inline uint32_t get_table_index(uint32_t vaddr);


lock_t page_lock;

page_status_t total_pages[PAGEABLE_PAGES];

/* Find a page thats free, else select the first unpinned page  */
uint32_t page_alloc(int pin)
{
    
    int temp = -1;
   
    void swap_page(int);

    /* Checks for a free page */
    for(int i = 0; i < PAGEABLE_PAGES; i++)
    {
        
        if(total_pages[i].free == 1)
        {
          
            temp = total_pages[i].id;
            break;
        }
    }

    /*  
     * finds the first unpinned page 
     */
    if(temp == -1)
    {   int j;
        /* check all the pages to fid the first unpinned page */
        for(j = 0; j < PAGEABLE_PAGES; j++)
        {
            
            if(total_pages[j].pinned == 0)
            {
             
                temp = total_pages[j].id;
                break;
            }
        }

        swap_page(j);
    }

     total_pages[temp].free = 0;
     total_pages[temp].pinned = pin;

    /* Find the address of our page which we are going to use */
    uint32_t adr = MEM_START + (temp * PAGE_SIZE);

    /* Sets all values in the allocateded page memory to zero */
    bzero((char*)adr, PAGE_SIZE);

    /* returns address of the page */
    return adr;
}

/*
 * Maps a page as present in the page table.
 *
 * 'vaddr' is the virtual address which is mapped to the physical
 * address 'paddr'.
 *
 * If user is nonzero, the page is mapped as accessible from a user
 * application.
 */
inline void table_map_present(uint32_t *table, uint32_t vaddr, uint32_t paddr, int user) {
	int access = PE_RW | PE_P, index = get_table_index(vaddr);

	if (user) 
		access |= PE_US;

	table[index] = (paddr & ~PAGE_MASK) | access;

   
}

/*
 * Make an entry in the page directory pointing to the given page
 * table.  vaddr is the virtual address the page table start with
 * table is the physical address of the page table
 *
 * If user is nonzero, the page is mapped as accessible from a user
 * application.
 */
inline void directory_insert_table(uint32_t *directory, uint32_t vaddr, uint32_t *table, int user) {
	int access = PE_RW | PE_P, index = get_directory_index(vaddr);
	uint32_t taddr;

	if (user)
		access |= PE_US;

	taddr = (uint32_t)table;

	directory[index] = (taddr & ~PAGE_MASK) | access;
}

/*
 * This sets up mapping for memory that should be shared between the
 * kernel and the user process. We need this since an interrupt or
 * exception doesn't change to another page directory, and we need to
 * have the kernel mapped in to handle the interrupts. So essentially
 * the kernel needs to be mapped into the user process address space.
 *
 * The user process can't access the kernel internals though, since
 * the processor checks the privilege level set on the pages and we
 * only set USER privileges on the pages the user process should be
 * allowed to access.
 *
 * Note:
 * - we identity map the pages, so that physical address is
 *   the same as the virtual address.
 *
 * - The user processes need access video memory directly, so we set
 *   the USER bit for the video page if we make this map in a user
 *   directory.
 */
static void make_common_map(uint32_t *page_directory, int user) {
	uint32_t addr;

	/* Allocate memory for the page table  */
	uint32_t page_table = page_alloc(1);

	/*
	 * Identity map in the rest of the physical memory so the
	 * kernel can access everything in memory directly.
	 */
	for (addr = 0; addr < MAX_PHYSICAL_MEMORY; addr += PAGE_SIZE)
		table_map_present((uint32_t *)page_table, addr, addr, 0);

	/* Identity map the video memory, from 0xb8000-0xb8fff. */
	table_map_present((uint32_t *) page_table, (uint32_t)SCREEN_ADDR, (uint32_t)SCREEN_ADDR, user);

	/*
	 * Insert in page_directory an entry for virtual address 0
	 * that points to physical address of page_table.
	 */
	directory_insert_table(page_directory, 0, (uint32_t *)page_table, user);
}


/*
 * init_memory()
 *
 * called once by _start() in kernel.c
 * You need to set up the virtual memory map for the kernel here.
 */
void init_memory(void) {
    /* Aquire lock for the page */
    lock_init(&page_lock);
    
    /* Initalize all values in every page */
    for(int i = 0; i < PAGEABLE_PAGES; i++)
    {
        total_pages[i].id = i;
        total_pages[i].free = 1;
        total_pages[i].pinned = 0;
    }
    
    /* create kernel page directory and page tabel */
    uint32_t address = page_alloc(1);
    kernel_page_dir = (uint32_t*)address;
   

    /* map the entire memory */
    make_common_map((uint32_t*)address, 0);
}

/*
 * Sets up a page directory and page table for a new process or thread.
 */
void setup_page_table(pcb_t *p) {

    lock_acquire(&page_lock);
   /* in case of a thread return kernel page directory for memory access  */
    if(p->is_thread == TRUE)
    {
        p->page_directory = kernel_page_dir;
        lock_release(&page_lock);
        return;
    }
    
    
    /* allocates a page directory  */
    uint32_t directory = page_alloc(1);

    /* first index of a directory should point to a kernel page table */
    make_common_map((uint32_t*)directory, 1);

    /* allocate a stack table for every process */
    uint32_t stack_table = page_alloc(1);
    
    /* insert the stack table into its directory */
    directory_insert_table((uint32_t*)directory, p->user_stack, (uint32_t*)stack_table, 1);

    /* allocates a stack table entry which maps the p->user_stack */
    uint32_t stack_page = page_alloc(1);

    table_map_present((uint32_t*)(stack_table & PE_BASE_ADDR_MASK), p->user_stack, stack_page, 1);

    p->page_directory = (uint32_t*)directory;

    lock_release(&page_lock);
}


int get_sector_num(page_status_t *page)
{    /* this aligns the page frame to its boundry*/
    uint32_t temp = page->virtual_address & PE_BASE_ADDR_MASK;
     /* base sector number plus number of sectors(offset) where the page is actually present*/
    uint32_t tmp = page->swap_loc + ((temp - current_running->start_pc) / SECTOR_SIZE);
   
    return tmp;
    /* alternative formula
     return page->swap_loc + ( ((page->virtual_address - current_running->start_pc) / PAGE_SIZE) * SECTORS_PER_PAGE ) ;*/
}



/*
 * called by exception_14 in interrupt.c (the faulting address is in
 * current_running->fault_addr)
 *
 * Interrupts are on when calling this function.
 */
void page_fault_handler(void) {

    lock_acquire(&page_lock);

    /*the fault virtual address */
    uint32_t vAdr = current_running->fault_addr;
    /*allocating a page for storing the read data from the disc */
    uint32_t adr = page_alloc(0);
   /*retrieving page number to store valuable information  */
    int index = (adr - MEM_START) / PAGE_SIZE;
    total_pages[index].swap_loc = current_running->swap_loc;
    total_pages[index].virtual_address = current_running->fault_addr;
    total_pages[index].swap_size = current_running->swap_size;
    
    /* valuable information is used to get the sector number where the fault page is present */
    uint32_t sector_num = (uint32_t)get_sector_num(&total_pages[index]);

      /* in case of a regular page frame */
     if ((sector_num + SECTORS_PER_PAGE) <= (total_pages[index].swap_loc + total_pages[index].swap_size))
        scsi_read(sector_num,SECTORS_PER_PAGE,(char*)adr);
   
   /* in case is it is the last page (optional since page alignment is already taken care of) */
     else {  
    uint32_t diff = (sector_num + SECTORS_PER_PAGE) - (total_pages[index].swap_loc + total_pages[index].swap_size);
     scsi_read(sector_num, SECTORS_PER_PAGE - diff, (char *)adr); 
    }   

    uint32_t directory_index = get_directory_index(vAdr);
     /* iextracting out the bit that tells if a page table address is present or not */
    int present_bit = current_running->page_directory[directory_index] & 1;
      /* indicates the presence of a page table, thus no need to set up a page table*/
    if(present_bit == 1)
    {
        table_map_present((current_running->page_directory[directory_index] & PE_BASE_ADDR_MASK ), vAdr, adr, 1);
    }else if (present_bit == 0)   /* indicates the absence of a page table, thus it must be allocated first */
    {
        uint32_t table = page_alloc(1);
        directory_insert_table(current_running->page_directory, vAdr, (uint32_t*) table, 1);
     
        table_map_present((current_running->page_directory[directory_index] & PE_BASE_ADDR_MASK ) , vAdr, adr, 1);
    }

    lock_release(&page_lock);
}


void swap_page(int i)
{    /* getting the sector number so that the data can be written into the appropriate sector
         ,regardless of the dirty bit */
    uint32_t disk_sector = (uint32_t)get_sector_num(&total_pages[i]);

    uint32_t physical_add = MEM_START + i * PAGE_SIZE;  
    /* in case of a regular page frame */
   if ((disk_sector + SECTORS_PER_PAGE) <= (total_pages[i].swap_loc + total_pages[i].swap_size))
    scsi_write(disk_sector, SECTORS_PER_PAGE, (char *)physical_add); 
  
    /* in case is it is the last page (optional since page alignment is already taken care of) */
   else {  
    uint32_t diff = (disk_sector + SECTORS_PER_PAGE) - (total_pages[i].swap_loc + total_pages[i].swap_size);
    scsi_write(disk_sector, SECTORS_PER_PAGE - diff, (char *)physical_add); 
  }
 

  total_pages[i].free = 1; 
    /*removing the mapping of the virtual to physical address as it is no longer present in tlb  */
  flush_tlb_entry(total_pages[i].virtual_address);
}